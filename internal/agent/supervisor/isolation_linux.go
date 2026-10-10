//go:build linux && !android

package supervisor

import (
	"fmt"

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
//	  chain ct_pre  { hook prerouting priority raw;  per slot: iifname tp-spaceN ct zone set N+1 }
//	  chain ct_out  { hook output     priority raw;  per slot: oifname tp-spaceN ct zone set N+1 }
//	  chain antispoof_fwd { hook forward priority -10; per slot: iifname tp-spaceN, source not the slot's transit addr, drop }
//	  chain antispoof_in  { hook input   priority -10; the same }
//	  chain forward { hook forward priority filter; iifname/oifname tp-space* drop }   (TP-014 adds egress accepts before these)
//	  chain input   { hook input   priority filter; iifname tp-space* ct state established,related accept; iifname tp-space* drop }
//	}
//	table arp thinkpol-supervisor-arp {
//	  chain input { hook input priority filter; iifname tp-space* drop }
//	}
//
// Per-space conntrack zones (ct_pre/ct_out) keep a space's connections out of
// the root namespace's zone 0, so a space can't forge a packet that conntrack
// counts as established or related to a root flow. Anti-spoof drops any packet
// from a space whose source isn't that slot's transit address, before any
// accept, so a space can't source-spoof. Permanent neighbour entries on both
// veth ends (see wire) make ARP and ND unnecessary for real traffic, so the
// arp table drops a space's ARP and the generic input chain drops its ND,
// neither of which can then flood the root namespace's neighbour table.
// Egress (TP-014) regenerates these tables with its accepts.

// zone is slot n's conntrack zone: nonzero, so a space's connections never
// share conntrack with the root namespace's (zone 0).
func zone(slot int) uint16 { return uint16(slot + 1) }

// slotRule is one slot's isolation: its veth end, its transit source
// addresses and its conntrack zone.
type slotRule struct {
	link           string
	v4addr, v6addr []byte // the slot's transit source addresses
	zone           uint16
}

func (s *Supervisor) slotRules(slots []int) []slotRule {
	out := make([]slotRule, 0, len(slots))
	for _, slot := range slots {
		t := s.opts.transit(slot)
		v4 := t.space[0].Addr().As4()
		v6 := t.space[1].Addr().As16()
		out = append(out, slotRule{
			link:   linkName(slot),
			v4addr: v4[:],
			v6addr: v6[:],
			zone:   zone(slot),
		})
	}
	return out
}

// applyIsolation rebuilds both tables from the active slots in one flush.
func (s *Supervisor) applyIsolation(slots []int) error {
	rules := s.slotRules(slots)
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
	base := func(table *nftables.Table, name string, hook *nftables.ChainHook, prio nftables.ChainPriority) *nftables.Chain {
		return c.AddChain(&nftables.Chain{
			Name: name, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: hook, Priority: nftables.ChainPriorityRef(prio), Policy: &accept,
		})
	}
	ctPre := base(inet, "ct_pre", nftables.ChainHookPrerouting, *nftables.ChainPriorityRaw)
	ctOut := base(inet, "ct_out", nftables.ChainHookOutput, *nftables.ChainPriorityRaw)
	antiFwd := base(inet, "antispoof_fwd", nftables.ChainHookForward, -10)
	antiIn := base(inet, "antispoof_in", nftables.ChainHookInput, -10)
	forward := base(inet, "forward", nftables.ChainHookForward, *nftables.ChainPriorityFilter)
	input := base(inet, "input", nftables.ChainHookInput, *nftables.ChainPriorityFilter)
	// The arp family has input and output hooks only (ARP is link-local, not
	// forwarded), so a space's ARP is dropped on input.
	arpIn := base(arp, "input", nftables.ChainHookInput, *nftables.ChainPriorityFilter)

	add := func(chain *nftables.Chain, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs})
	}

	// Per-slot: conntrack zone, then anti-spoof.
	for _, r := range rules {
		add(ctPre, zoneSet(expr.MetaKeyIIFNAME, r.link, r.zone)...)
		add(ctOut, zoneSet(expr.MetaKeyOIFNAME, r.link, r.zone)...)
		for _, chain := range []*nftables.Chain{antiFwd, antiIn} {
			add(chain, antiSpoof(r.link, unix.NFPROTO_IPV4, 12, r.v4addr)...)
			add(chain, antiSpoof(r.link, unix.NFPROTO_IPV6, 8, r.v6addr)...)
		}
	}

	// Generic: nothing forwarded from or to a space.
	add(forward, drop(spaceLink(expr.MetaKeyIIFNAME))...)
	add(forward, drop(spaceLink(expr.MetaKeyOIFNAME))...)
	// Input: a space reaches nothing of the root namespace's own, past
	// replies to what the root namespace started (in the space's own zone).
	add(input, established(spaceLink(expr.MetaKeyIIFNAME))...)
	add(input, drop(spaceLink(expr.MetaKeyIIFNAME))...)
	// ARP from a space never reaches the root namespace's neighbour table.
	add(arpIn, drop(spaceLink(expr.MetaKeyIIFNAME))...)

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: apply isolation (%d slots): %w", len(slots), err)
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

// antiSpoof is "iifname == link; nfproto == fam; <L3 source at off> != addr; drop".
func antiSpoof(link string, nfproto byte, off uint32, addr []byte) []expr.Any {
	return append(linkExact(expr.MetaKeyIIFNAME, link),
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: uint32(len(addr))},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: addr},
		&expr.Verdict{Kind: expr.VerdictDrop},
	)
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
	return append(match, &expr.Verdict{Kind: expr.VerdictDrop})
}

// spaceLink matches packets whose interface (key: in or out) starts with the
// link prefix: a compare on the first bytes, how nft matches "tp-space*".
func spaceLink(key expr.MetaKey) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(LinkPrefix)},
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
