//go:build linux && !android

package supervisor

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// The root namespace is the only place the spaces' veths meet, so it is
// where they are kept apart (PRD "Isolation"): a worker holds NET_ADMIN only
// inside its own user namespace, but it still owns its veth, so the
// separation can't rely on the spaces' routes or on the kernel trusting a
// space's packets. The supervisor's tables, rebuilt from the whole set of
// slots on every change (one atomic flush), in the root namespace:
//
//	table inet thinkpol-supervisor {
//	  chain antispoof { hook prerouting priority raw - 10;
//	    per slot: iifname tp-spaceN, source not the slot's transit address: drop }
//	  chain ct_pre { hook prerouting priority raw;
//	    per slot: iifname tp-spaceN daddr <the root end's transit address> ct zone set N+1
//	              iifname tp-spaceN meta pkttype != host ct zone set N+1 }
//	  chain ct_out { hook output priority raw; per slot: oifname tp-spaceN ct zone set N+1 }
//	  chain forward { hook forward priority filter;
//	    iifname tp-space* ct state invalid,untracked drop
//	    per slot: iifname != tp-space* oifname tp-spaceN ct state established,related
//	              ct original saddr <the slot's transit address> accept
//	    oifname tp-space* drop
//	    iifname tp-space* goto space_out
//	    per family whose forwarding the supervisor turned on:
//	      iifname != tp-space* oifname != tp-space* meta nfproto <family> drop }
//	  chain space_out {
//	    per slot: iifname tp-spaceN ct state new ct count over <MaxFlowsPerSpace> drop
//	    daddr in EgressAllowed goto space_accept
//	    daddr in egressBlocked or a transit range drop
//	    goto space_accept }
//	  chain space_accept {
//	    per slot and family with egress: iifname tp-spaceN oifname <uplink> meta nfproto <family>
//	              ct original saddr <the slot's transit address> accept
//	    per slot and dial: iifname tp-spaceN oifname <uplink> daddr A meta l4proto <proto> th dport P
//	              ct original saddr <the slot's transit address> accept
//	    drop }
//	  chain input { hook input priority filter;
//	    per slot: iifname tp-spaceN ct state established ct original daddr <the slot's transit address> accept
//	    iifname tp-space* drop }
//	  chain postrouting { type nat hook postrouting priority srcnat;
//	    oifname != tp-space* saddr in <a transit range> masquerade to :MasqueradePorts }
//	  chain postrouting_guard { hook postrouting priority srcnat + 10;
//	    oifname != tp-space* saddr in <a transit range> drop }
//	}
//	table arp thinkpol-supervisor-arp {
//	  chain input { hook input priority filter; iifname tp-space* drop }
//	}
//
// What keeps spaces apart from each other and from the root namespace's own
// flows is two things. Anti-spoof runs before conntrack sees a packet: a
// space's packets carry its own transit address as their source, or are
// dropped. And every accept is bound to the slot that owns the conntrack
// entry, by the entry's original-direction addresses: a space's flows
// started from its transit address, the root's flows with a space went to
// it. Conntrack takes an ICMP error as "related" to whichever flow its inner
// header quotes, so a space quoting another space's flow, or a root flow,
// in an error it forges gets the other flow's entry, which no accept of its
// own slot matches; the input chain takes no "related" at all, so a forged
// "port unreachable" or "fragmentation needed" never reaches the root's
// sockets or its route cache.
//
// Conntrack zones are belt and braces: what a space exchanges with its end
// of the veth pair (its gateway) or broadcasts, and what the root namespace
// sends a space, is tracked in the space's own zone. What a space sends on
// (egress, its dials) stays in zone 0, with the root's own flows: replies
// arrive by the uplink, before anything could tell their zone, and must
// find their flow to be un-NATed. (nftables can set a zone for the original
// direction only, which would solve that, but google/nftables can't express
// it, and "fib daddr type", which would let the zone follow the destination,
// isn't in every kernel.)
//
// Egress opens exactly what is masqueraded: a space with egress may send to
// the internet by the uplink, in the families granted and carried; every
// space may reach the endpoints its own section dials (other servers), by
// the uplink, in their transport's protocol, egress or not. Destinations no
// space reaches are dropped first (egressBlocked: metadata services,
// link-local and private networks, the transit ranges), unless
// EgressAllowed names them. The space SNATs its overlay to its transit
// address inside its namespace (applySpaceTable), so the root only ever sees
// transit sources; it masquerades exactly the transit ranges, and drops a
// transit source about to leave unmasqueraded. A space's new flows through
// the root are capped (MaxFlowsPerSpace), so it can't fill the node's
// conntrack table. Where the supervisor turned the root namespace's
// forwarding on itself, nothing but the spaces' traffic is forwarded.
// Permanent neighbour entries on both veth ends (see wire) make ARP and ND
// unnecessary for real traffic: the arp table drops a space's ARP, and
// anti-spoof its ND (whose sources are link-local), so neither floods the
// root's neighbour table.

// connlimitOver is NFT_CONNLIMIT_F_INV: the connlimit expression matches
// above its count. ctDirOriginal is IP_CT_DIR_ORIGINAL.
const (
	connlimitOver = 1
	ctDirOriginal = 0
)

// slotZone is slot n's conntrack zone: nonzero, so what a space exchanges
// with the root namespace itself never shares conntrack with the root's own
// flows (zone 0).
func slotZone(slot int) uint16 { return uint16(slot + 1) }

// slotRule is one slot's part of the tables: its veth end, its transit
// addresses, its conntrack zone and what it may send on.
type slotRule struct {
	link string
	src  [2]netip.Addr // the slot's transit addresses, IPv4 and IPv6
	gw   [2]netip.Addr // the root end's transit addresses
	zone uint16
	// egress are the families it may send to the internet: granted, and
	// carried by the uplink.
	egress [2]bool
	dials  []Dial
}

// tableState is everything the root namespace's tables are built from.
type tableState struct {
	rules []slotRule
	// uplink is the node's uplink; empty: no egress, no dials.
	uplink string
	// owned are the families whose forwarding the supervisor turned on.
	owned [2]bool
	// maxFlows caps each space's flows through the root; 0: no cap.
	maxFlows int
}

// tableState snapshots what the tables need; the caller holds s.mu.
func (s *Supervisor) tableState() tableState {
	st := tableState{uplink: s.uplink.Name, owned: s.forwarding.owned(), maxFlows: s.maxFlows}
	for _, w := range s.workers {
		grant, dials := w.egressRules()
		st.rules = append(st.rules, slotRule{
			link:   w.link,
			src:    [2]netip.Addr{w.transit.space[0].Addr(), w.transit.space[1].Addr()},
			gw:     [2]netip.Addr{w.transit.root[0].Addr(), w.transit.root[1].Addr()},
			zone:   slotZone(w.slot),
			egress: s.effective(grant),
			dials:  dials,
		})
	}
	return st
}

// effective are the families of grant the uplink carries; the caller holds
// s.mu.
func (s *Supervisor) effective(grant EgressGrant) [2]bool {
	if s.uplink.Name == "" {
		return [2]bool{}
	}
	return [2]bool{grant.IPv4 && s.uplink.IPv4, grant.IPv6 && s.uplink.IPv6}
}

// applyIsolation rebuilds both tables in one flush.
func (s *Supervisor) applyIsolation(st tableState) error {
	if fn := s.opts.failIsolation; fn != nil {
		if err := fn(len(st.rules)); err != nil {
			return err
		}
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	r := newRules(c, s.opts.unboundAccepts)
	r.addAntiSpoof(st)
	r.addZones(st)
	r.addForward(st)
	r.addSpaceOut(st, s.opts)
	r.addSpaceAccept(st)
	r.addInput(st)
	r.addMasquerade(s.opts)
	r.addArp()
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: apply isolation (%d slots): %w", len(st.rules), err)
	}
	return nil
}

// rules assembles the supervisor's tables: the kernel connection, the two
// tables and their chains, and where each per-chain builder below adds its
// rules. unboundAccepts is the forged-ICMP tests' negative control (Options
// documents it); the accepts then take any established or related flow,
// whoever owns it.
type rules struct {
	c                                                                                 *nftables.Conn
	unboundAccepts                                                                    bool
	inet, arp                                                                         *nftables.Table
	antiSpoof, ctPre, ctOut, forward, spaceOut, spaceAccept, input, nat, guard, arpIn *nftables.Chain
}

// newRules replaces the supervisor's tables atomically (add-then-delete-
// then-add, whether or not they, or a dead supervisor's, were there) and
// creates their chains.
func newRules(c *nftables.Conn, unboundAccepts bool) *rules {
	r := &rules{
		c:              c,
		unboundAccepts: unboundAccepts,
		inet:           &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName},
		arp:            &nftables.Table{Family: nftables.TableFamilyARP, Name: ArpTableName},
	}
	for _, t := range []*nftables.Table{r.inet, r.arp} {
		c.AddTable(t)
		c.DelTable(t)
		c.AddTable(t)
	}
	accept := nftables.ChainPolicyAccept
	filter := nftables.ChainTypeFilter
	base := func(table *nftables.Table, name string, typ nftables.ChainType, hook *nftables.ChainHook, prio nftables.ChainPriority) *nftables.Chain {
		return c.AddChain(&nftables.Chain{
			Name: name, Table: table, Type: typ,
			Hooknum: hook, Priority: nftables.ChainPriorityRef(prio), Policy: &accept,
		})
	}
	regular := func(name string) *nftables.Chain { return c.AddChain(&nftables.Chain{Name: name, Table: r.inet}) }
	r.antiSpoof = base(r.inet, "antispoof", filter, nftables.ChainHookPrerouting, *nftables.ChainPriorityRaw-10)
	r.ctPre = base(r.inet, "ct_pre", filter, nftables.ChainHookPrerouting, *nftables.ChainPriorityRaw)
	r.ctOut = base(r.inet, "ct_out", filter, nftables.ChainHookOutput, *nftables.ChainPriorityRaw)
	r.forward = base(r.inet, "forward", filter, nftables.ChainHookForward, *nftables.ChainPriorityFilter)
	r.spaceOut, r.spaceAccept = regular("space_out"), regular("space_accept")
	r.input = base(r.inet, "input", filter, nftables.ChainHookInput, *nftables.ChainPriorityFilter)
	r.nat = base(r.inet, "postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, *nftables.ChainPriorityNATSource)
	r.guard = base(r.inet, "postrouting_guard", filter, nftables.ChainHookPostrouting, *nftables.ChainPriorityNATSource+10)
	// The arp family has input and output hooks only (ARP is link-local, not
	// forwarded), so a space's ARP is dropped on input.
	r.arpIn = base(r.arp, "input", filter, nftables.ChainHookInput, *nftables.ChainPriorityFilter)
	return r
}

// add adds one rule to a chain.
func (r *rules) add(chain *nftables.Chain, exprs ...expr.Any) {
	r.c.AddRule(&nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs})
}

// addAntiSpoof is, per slot, "source not the slot's transit address: drop",
// before conntrack sees a packet.
func (r *rules) addAntiSpoof(st tableState) {
	for _, sr := range st.rules {
		for _, a := range sr.src {
			r.add(r.antiSpoof, antiSpoof(sr.link, a)...)
		}
	}
}

// addZones puts what is the root namespace's own business (a space's
// exchange with its end of the veth pair, and its broadcasts, and what the
// root namespace sends a space) in the slot's own conntrack zone.
func (r *rules) addZones(st tableState) {
	for _, sr := range st.rules {
		for _, gw := range sr.gw {
			r.add(r.ctPre, all(linkExact(expr.MetaKeyIIFNAME, sr.link), daddrIn(netip.PrefixFrom(gw, gw.BitLen())), zone(sr.zone))...)
		}
		r.add(r.ctPre, all(linkExact(expr.MetaKeyIIFNAME, sr.link), notHost(), zone(sr.zone))...)
		r.add(r.ctOut, all(linkExact(expr.MetaKeyOIFNAME, sr.link), zone(sr.zone))...)
	}
}

// addForward decides what is forwarded at all: nothing conntrack can't
// place; replies to what each space sent on, bound to its slot; nothing
// else to a space; what a space sends goes by space_out; and, where the
// supervisor turned forwarding on, nothing else at all.
func (r *rules) addForward(st tableState) {
	r.add(r.forward, drop(all(spaceLink(expr.MetaKeyIIFNAME), ctState(expr.CtStateBitINVALID|expr.CtStateBitUNTRACKED)))...)
	for _, sr := range st.rules {
		for _, a := range sr.src {
			r.add(r.forward, all(spaceLinkNot(expr.MetaKeyIIFNAME), linkExact(expr.MetaKeyOIFNAME, sr.link),
				ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), r.ctOriginal(expr.CtKeySRC, a), verdict(expr.VerdictAccept))...)
		}
	}
	r.add(r.forward, drop(spaceLink(expr.MetaKeyOIFNAME))...)
	r.add(r.forward, all(spaceLink(expr.MetaKeyIIFNAME), jump(r.spaceOut))...)
	for i, nfproto := range []byte{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
		if st.owned[i] {
			r.add(r.forward, drop(all(spaceLinkNot(expr.MetaKeyIIFNAME), spaceLinkNot(expr.MetaKeyOIFNAME), nfprotoIs(nfproto)))...)
		}
	}
}

// addSpaceOut caps each space's new flows through the root (the flow cap),
// then refuses the destinations no space reaches (egressBlocked and the
// transit ranges, less what EgressAllowed names).
func (r *rules) addSpaceOut(st tableState, opts Options) {
	if st.maxFlows > 0 {
		for _, sr := range st.rules {
			r.add(r.spaceOut, drop(all(linkExact(expr.MetaKeyIIFNAME, sr.link), ctState(expr.CtStateBitNEW),
				[]expr.Any{&expr.Connlimit{Count: uint32(st.maxFlows), Flags: connlimitOver}}))...)
		}
	}
	for _, p := range opts.EgressAllowed {
		r.add(r.spaceOut, all(daddrIn(p), jump(r.spaceAccept))...)
	}
	for _, p := range append(egressBlocked, opts.TransitIPv4, opts.TransitIPv6) {
		r.add(r.spaceOut, drop(daddrIn(p))...)
	}
	r.add(r.spaceOut, jump(r.spaceAccept)...)
}

// addSpaceAccept opens, out of the uplink, each slot's egress and its
// dials, for the slot's own flows only.
func (r *rules) addSpaceAccept(st tableState) {
	if st.uplink != "" {
		for _, sr := range st.rules {
			for i, a := range sr.src {
				if sr.egress[i] {
					r.add(r.spaceAccept, all(linkExact(expr.MetaKeyIIFNAME, sr.link), linkExact(expr.MetaKeyOIFNAME, st.uplink),
						r.ctOriginal(expr.CtKeySRC, a), verdict(expr.VerdictAccept))...)
				}
			}
			for _, d := range sr.dials {
				a := sr.src[0]
				if !d.Address.Addr().Unmap().Is4() {
					a = sr.src[1]
				}
				r.add(r.spaceAccept, all(linkExact(expr.MetaKeyIIFNAME, sr.link), linkExact(expr.MetaKeyOIFNAME, st.uplink),
					dialMatch(d), r.ctOriginal(expr.CtKeySRC, a), verdict(expr.VerdictAccept))...)
			}
		}
	}
	r.add(r.spaceAccept, drop(nil)...)
}

// addInput lets a space reach nothing of the root namespace's own, past
// replies to what the root namespace started with it.
func (r *rules) addInput(st tableState) {
	for _, sr := range st.rules {
		for _, a := range sr.src {
			state := expr.CtStateBitESTABLISHED
			if r.unboundAccepts {
				state |= expr.CtStateBitRELATED
			}
			r.add(r.input, all(linkExact(expr.MetaKeyIIFNAME, sr.link), ctState(state),
				r.ctOriginal(expr.CtKeyDST, a), verdict(expr.VerdictAccept))...)
		}
	}
	r.add(r.input, drop(spaceLink(expr.MetaKeyIIFNAME))...)
}

// addMasquerade masquerades the transit ranges wherever they leave but to
// a space, within MasqueradePorts; anything still from a transit range
// after that is dropped.
func (r *rules) addMasquerade(opts Options) {
	for _, p := range []netip.Prefix{opts.TransitIPv4, opts.TransitIPv6} {
		r.add(r.nat, masquerade(p)...)
		r.add(r.guard, drop(all(spaceLinkNot(expr.MetaKeyOIFNAME), addrIn(p, srcOffset(p.Addr()))))...)
	}
}

// addArp keeps ARP from a space away from the root namespace's neighbour
// table.
func (r *rules) addArp() {
	r.add(r.arpIn, drop(spaceLink(expr.MetaKeyIIFNAME))...)
}

// installIsolation sets up the tables with no slots yet.
func (s *Supervisor) installIsolation() error {
	s.mu.Lock()
	st := s.tableState()
	s.mu.Unlock()
	return s.applyIsolation(st)
}

// zone is "ct zone set <z>".
func zone(z uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint16(z)},
		&expr.Ct{Register: 1, SourceRegister: true, Key: expr.CtKeyZONE},
	}
}

// notHost is "meta pkttype != host": broadcast and multicast frames.
func notHost() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPKTTYPE, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{unix.PACKET_HOST}},
	}
}

// ctState is "ct state & bits != 0".
func ctState(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(bits), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}

// ctOriginal is "nfproto == a's family; ct original <saddr|daddr> == a": the
// conntrack entry's original-direction address. In the inet family the
// kernel loads the whole 16-byte tuple address; an IPv4 one is its first 4
// bytes. (google/nftables sends the direction as 4 bytes, of which the
// kernel reads the first: 0, the original direction, is all this asks.)
func (r *rules) ctOriginal(key expr.CtKey, a netip.Addr) []expr.Any {
	if r.unboundAccepts {
		return family(a)
	}
	return append(family(a),
		&expr.Ct{Register: 1, Key: key, Direction: ctDirOriginal},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a.AsSlice()},
	)
}

// antiSpoof is "iifname == link; nfproto == addr's family; source != addr;
// drop".
func antiSpoof(link string, addr netip.Addr) []expr.Any {
	return append(linkExact(expr.MetaKeyIIFNAME, link), append(family(addr),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: srcOffset(addr), Len: uint32(addr.BitLen() / 8)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: addr.AsSlice()},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)...)
}

// dialMatch is "daddr == d's address; meta l4proto == d's protocol; th dport
// == d's port".
func dialMatch(d Dial) []expr.Any {
	a := d.Address.Addr().Unmap()
	proto := byte(unix.IPPROTO_UDP)
	if d.Network == "tcp" {
		proto = unix.IPPROTO_TCP
	}
	return append(daddrIn(netip.PrefixFrom(a, a.BitLen())),
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, d.Address.Port())},
	)
}

// masquerade is "oifname != tp-space*; nfproto == p's family; saddr in p;
// masquerade to :MasqueradePorts". The space's own SNAT already picked a
// fully random port in that range (applySpaceTable), which the masquerade
// keeps unless another flow holds it.
func masquerade(p netip.Prefix) []expr.Any {
	return append(append(spaceLinkNot(expr.MetaKeyOIFNAME), addrIn(p, srcOffset(p.Addr()))...),
		&expr.Immediate{Register: 2, Data: binary.BigEndian.AppendUint16(nil, MasqueradePorts[0])},
		&expr.Immediate{Register: 3, Data: binary.BigEndian.AppendUint16(nil, MasqueradePorts[1])},
		&expr.Masq{ToPorts: true, RegProtoMin: 2, RegProtoMax: 3},
	)
}

// daddrIn is "nfproto == p's family; daddr in p".
func daddrIn(p netip.Prefix) []expr.Any { return addrIn(p, dstOffset(p.Addr())) }

// addrIn is "nfproto == p's family; <network header at off> in p".
func addrIn(p netip.Prefix, off uint32) []expr.Any {
	p = p.Masked()
	n := uint32(p.Addr().BitLen() / 8)
	mask := make([]byte, n)
	for i := range p.Bits() {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	return append(family(p.Addr()),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: mask, Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()},
	)
}

// family is "meta nfproto == a's family".
func family(a netip.Addr) []expr.Any {
	if a.Is4() {
		return nfprotoIs(unix.NFPROTO_IPV4)
	}
	return nfprotoIs(unix.NFPROTO_IPV6)
}

func nfprotoIs(nfproto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
	}
}

// srcOffset and dstOffset are where the network header holds a's family's
// source and destination addresses.
func srcOffset(a netip.Addr) uint32 {
	if a.Is4() {
		return 12
	}
	return 8
}

func dstOffset(a netip.Addr) uint32 {
	if a.Is4() {
		return 16
	}
	return 24
}

// established is "<match>; ct state established,related; accept".
func established(match []expr.Any) []expr.Any {
	return append(append(match, ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)...),
		&expr.Verdict{Kind: expr.VerdictAccept})
}

func drop(match []expr.Any) []expr.Any {
	return append(match, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
}

// all is the concatenation of match groups into one rule's expressions.
func all(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// verdict is a bare accept-or-drop expression.
func verdict(kind expr.VerdictKind) []expr.Any { return []expr.Any{&expr.Verdict{Kind: kind}} }

// jump is "goto to".
func jump(to *nftables.Chain) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictGoto, Chain: to.Name}}
}

// spaceLink matches packets whose interface (key: in or out) starts with the
// link prefix: a compare on the first bytes, how nft matches "tp-space*".
func spaceLink(key expr.MetaKey) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(LinkPrefix)},
	}
}

// spaceLinkNot matches packets whose interface doesn't start with the link
// prefix.
func spaceLinkNot(key expr.MetaKey) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte(LinkPrefix)},
	}
}

// linkExact matches one interface by its whole name (name plus the NUL
// terminator, as nft compares an exact iifname).
func linkExact(key expr.MetaKey, link string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(link), 0)},
	}
}

// removeIsolation deletes the supervisor's tables, if they are there.
func removeIsolation() error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	for _, t := range []*nftables.Table{
		{Family: nftables.TableFamilyINet, Name: TableName},
		{Family: nftables.TableFamilyARP, Name: ArpTableName},
	} {
		c.AddTable(t)
		c.DelTable(t)
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: remove isolation: %w", err)
	}
	return nil
}
