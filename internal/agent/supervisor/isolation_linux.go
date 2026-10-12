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
//	    per slot: iifname tp-spaceN fib daddr type != unicast ct zone set N+1 }
//	  chain ct_out { hook output priority raw; per slot: oifname tp-spaceN ct zone set N+1 }
//	  chain forward { hook forward priority filter;
//	    iifname != tp-space* oifname tp-space* ct state established,related accept
//	    oifname tp-space* drop
//	    iifname tp-space* daddr in egressBlocked (link-local, metadata, transit, …) drop
//	    per slot with egress: iifname tp-spaceN oifname <uplink> meta nfproto ipv4|ipv6 accept
//	    per slot, per dial: iifname tp-spaceN daddr A meta l4proto tcp|udp th dport P accept
//	    iifname tp-space* drop }
//	  chain input { hook input priority filter;
//	    iifname tp-space* ct state established,related accept; iifname tp-space* drop }
//	  chain postrouting { type nat hook postrouting priority srcnat;
//	    oifname != tp-space* ip saddr <TransitIPv4> masquerade
//	    oifname != tp-space* ip6 saddr <TransitIPv6> masquerade }
//	}
//	table arp thinkpol-supervisor-arp {
//	  chain input { hook input priority filter; iifname tp-space* drop }
//	}
//
// Anti-spoof runs before conntrack sees a packet: a space's packets carry
// its transit address as their source or are dropped, so a space can't
// forge a packet that conntrack would count as part of anyone else's flow
// (or update the state of one), whatever zone it lands in. What a space
// sends to the root namespace itself (local, broadcast and multicast
// destinations), and what the root namespace sends to a space, is tracked
// in the space's own conntrack zone, apart from the root's zone 0, so the
// input chain's "established" is only ever a reply to the root's own flow
// with that space. What a space sends on (egress, its dials) stays in zone
// 0: the replies come back by the uplink, before anything could tell which
// zone they belong to, and must find their flow there to be un-NATed
// (nftables can set a zone for the original direction only, which would
// keep replies in zone 0, but the library the supervisor uses can't express
// it). Its replies are recognised by conntrack after the masquerade is
// undone, which takes them back to the transit address, and so the veth, of
// the space whose flow it is.
//
// Egress (TP-014) opens exactly what is masqueraded: a space with egress
// may send to the internet by the uplink, the families it has, and every
// space may reach the endpoints its own section dials (other servers),
// egress or not. The worker SNATs its overlay to its transit address inside
// its namespace (spaceTable), so the root only ever sees transit sources,
// and masquerades exactly the transit ranges. Permanent neighbour entries
// on both veth ends (see wire) make ARP and ND unnecessary for real
// traffic: the arp table drops a space's ARP, and anti-spoof its ND (whose
// sources are link-local), so neither floods the root's neighbour table.

// failApplyIsolation makes applyIsolation fail when there are slots to apply,
// for the SetSpaces rollback test. Tests set it; it is never set in production.
var failApplyIsolation bool

// zone is slot n's conntrack zone: nonzero, so a space's connections with
// the root namespace never share conntrack with the root's own (zone 0).
func zone(slot int) uint16 { return uint16(slot + 1) }

// egressBlocked are destinations no space reaches through the root
// namespace, by egress or a dial: the provider's metadata services and
// link-local networks (credentials and the node's own configuration live
// there), the transit ranges (other spaces), and what is never routed to
// the internet. Provider-private networks (RFC 1918, ULA) aren't blocked:
// the lab's internet is one, and so are some providers' public ranges.
var egressBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/127"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

// slotRule is one slot's part of the tables: its veth end, its transit
// source addresses, its conntrack zone and what it may send on.
type slotRule struct {
	link   string
	v4, v6 netip.Addr // the slot's transit source addresses
	zone   uint16
	egress Egress
	dials  []netip.AddrPort
}

// slotRules are the active workers' rules; the caller holds s.mu.
func (s *Supervisor) slotRules() []slotRule {
	out := make([]slotRule, 0, len(s.workers))
	for _, w := range s.workers {
		t := w.transit
		e, dials := w.egressRules()
		out = append(out, slotRule{
			link:   w.link,
			v4:     t.space[0].Addr(),
			v6:     t.space[1].Addr(),
			zone:   zone(w.slot),
			egress: e,
			dials:  dials,
		})
	}
	return out
}

// applyIsolation rebuilds both tables from the active slots in one flush.
func (s *Supervisor) applyIsolation(rules []slotRule) error {
	if failApplyIsolation && len(rules) > 0 {
		return fmt.Errorf("supervisor: applyIsolation failed (injected)")
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}

	inet := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	arp := &nftables.Table{Family: nftables.TableFamilyARP, Name: ArpTableName}
	// Add-then-delete-then-add replaces each table atomically whether or not
	// it (or a dead supervisor's) was there.
	for _, t := range []*nftables.Table{inet, arp} {
		c.AddTable(t)
		c.DelTable(t)
		c.AddTable(t)
	}
	accept := nftables.ChainPolicyAccept
	base := func(table *nftables.Table, name string, typ nftables.ChainType, hook *nftables.ChainHook, prio nftables.ChainPriority) *nftables.Chain {
		return c.AddChain(&nftables.Chain{
			Name: name, Table: table, Type: typ,
			Hooknum: hook, Priority: nftables.ChainPriorityRef(prio), Policy: &accept,
		})
	}
	filter := nftables.ChainTypeFilter
	antiSpoofChain := base(inet, "antispoof", filter, nftables.ChainHookPrerouting, *nftables.ChainPriorityRaw-10)
	ctPre := base(inet, "ct_pre", filter, nftables.ChainHookPrerouting, *nftables.ChainPriorityRaw)
	ctOut := base(inet, "ct_out", filter, nftables.ChainHookOutput, *nftables.ChainPriorityRaw)
	forward := base(inet, "forward", filter, nftables.ChainHookForward, *nftables.ChainPriorityFilter)
	input := base(inet, "input", filter, nftables.ChainHookInput, *nftables.ChainPriorityFilter)
	nat := base(inet, "postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, *nftables.ChainPriorityNATSource)
	// The arp family has input and output hooks only (ARP is link-local, not
	// forwarded), so a space's ARP is dropped on input.
	arpIn := base(arp, "input", filter, nftables.ChainHookInput, *nftables.ChainPriorityFilter)

	add := func(chain *nftables.Chain, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs})
	}

	// Per slot: anti-spoof before conntrack, then the zone of what is the
	// root namespace's own business.
	for _, r := range rules {
		add(antiSpoofChain, antiSpoof(r.link, r.v4)...)
		add(antiSpoofChain, antiSpoof(r.link, r.v6)...)
		add(ctPre, notForwarded(r.link, r.zone)...)
		add(ctOut, zoneSet(expr.MetaKeyOIFNAME, r.link, r.zone)...)
	}

	// Forward: replies to what spaces sent on, then nothing else to a
	// space, nothing to where no space goes, what each space may send,
	// nothing else from a space.
	add(forward, established(append(spaceLinkNot(expr.MetaKeyIIFNAME), spaceLink(expr.MetaKeyOIFNAME)...))...)
	add(forward, drop(spaceLink(expr.MetaKeyOIFNAME))...)
	for _, p := range append(egressBlocked, s.opts.TransitIPv4, s.opts.TransitIPv6) {
		add(forward, drop(append(spaceLink(expr.MetaKeyIIFNAME), daddrIn(p)...))...)
	}
	for _, r := range rules {
		if r.egress.Uplink != "" {
			for _, fam := range []struct {
				on      bool
				nfproto byte
			}{{r.egress.IPv4, unix.NFPROTO_IPV4}, {r.egress.IPv6, unix.NFPROTO_IPV6}} {
				if fam.on {
					add(forward, egressAccept(r.link, r.egress.Uplink, fam.nfproto)...)
				}
			}
		}
		for _, d := range r.dials {
			for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				add(forward, dialAccept(r.link, d, proto)...)
			}
		}
	}
	add(forward, drop(spaceLink(expr.MetaKeyIIFNAME))...)

	// Input: a space reaches nothing of the root namespace's own, past
	// replies to what the root namespace started (in the space's own zone).
	add(input, established(spaceLink(expr.MetaKeyIIFNAME))...)
	add(input, drop(spaceLink(expr.MetaKeyIIFNAME))...)

	// Masquerade: the transit ranges, wherever they leave but to a space.
	add(nat, masquerade(s.opts.TransitIPv4)...)
	add(nat, masquerade(s.opts.TransitIPv6)...)

	// ARP from a space never reaches the root namespace's neighbour table.
	add(arpIn, drop(spaceLink(expr.MetaKeyIIFNAME))...)

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: apply isolation (%d slots): %w", len(rules), err)
	}
	return nil
}

// installIsolation sets up the tables with no slots yet.
func (s *Supervisor) installIsolation() error { return s.applyIsolation(nil) }

// zoneSet is "<key> == link; ct zone set <zone>".
func zoneSet(key expr.MetaKey, link string, z uint16) []expr.Any {
	return append(linkExact(key, link),
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint16(z)},
		&expr.Ct{Register: 1, SourceRegister: true, Key: expr.CtKeyZONE},
	)
}

// notForwarded is "iifname == link; fib daddr type != unicast; ct zone set
// <zone>": what a space sends to the root namespace itself (its local,
// broadcast and multicast addresses) is tracked in the space's zone; what
// it sends on, in zone 0 (see the package's tables above).
func notForwarded(link string, z uint16) []expr.Any {
	return append(linkExact(expr.MetaKeyIIFNAME, link),
		&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(unix.RTN_UNICAST)},
		&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint16(z)},
		&expr.Ct{Register: 1, SourceRegister: true, Key: expr.CtKeyZONE},
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

// egressAccept is "iifname == link; oifname == uplink; nfproto == fam;
// accept".
func egressAccept(link, uplink string, nfproto byte) []expr.Any {
	return append(append(linkExact(expr.MetaKeyIIFNAME, link), linkExact(expr.MetaKeyOIFNAME, uplink)...),
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// dialAccept is "iifname == link; daddr == d's address; meta l4proto ==
// proto; th dport == d's port; accept".
func dialAccept(link string, d netip.AddrPort, proto byte) []expr.Any {
	a := d.Addr().Unmap()
	return append(append(linkExact(expr.MetaKeyIIFNAME, link), daddrIn(netip.PrefixFrom(a, a.BitLen()))...),
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, d.Port())},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

// masquerade is "oifname != tp-space*; nfproto == p's family; saddr in p;
// masquerade".
func masquerade(p netip.Prefix) []expr.Any {
	return append(append(spaceLinkNot(expr.MetaKeyOIFNAME), addrIn(p, srcOffset(p.Addr()))...),
		&expr.Counter{},
		&expr.Masq{},
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
	nfproto := byte(unix.NFPROTO_IPV6)
	if a.Is4() {
		nfproto = unix.NFPROTO_IPV4
	}
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
	mask := binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	return append(match,
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	)
}

func drop(match []expr.Any) []expr.Any {
	return append(match, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
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
