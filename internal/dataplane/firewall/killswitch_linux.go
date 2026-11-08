//go:build linux && !android

package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The kill switch's nftables table: owned by its name, apart from the
// guard's, so a successor finds what a crashed or stopped run left.
const (
	KillSwitchTable = "thinkpol-killswitch"
	killSwitchSet4  = "allow4"
	killSwitchSet6  = "allow6"
	directSet4      = "direct4"
	directSet6      = "direct6"
)

// KillSwitch keeps everything but KillSwitchRules from leaving the
// device, both families, with one nftables table in a network namespace:
//
//	table inet thinkpol-killswitch {
//	  set allow4 { type ipv4_addr; flags interval; elements = <Allow's IPv4> }
//	  set allow6 { type ipv6_addr; flags interval; elements = <Allow's IPv6> }
//	  set direct4 { type ipv4_addr; flags interval,timeout; timeout 30s; elements = <Direct's IPv4> }
//	  set direct6 { type ipv6_addr; flags interval,timeout; timeout 30s; elements = <Direct's IPv6> }
//	  chain output { type filter hook output priority 2147483647; policy accept;
//	    oifname "lo" accept
//	    oifname <TUN> accept                                 (connected only)
//	    meta mark <Mark> accept
//	    meta nfproto ipv4 ip daddr @allow4 accept
//	    meta nfproto ipv6 ip6 daddr @allow6 accept
//	    meta nfproto ipv4 ip daddr @direct4 accept
//	    meta nfproto ipv6 ip6 daddr @direct6 accept
//	    meta nfproto ipv4 udp sport 68 udp dport 67 accept   (DHCPv4)
//	    meta nfproto ipv6 udp sport 546 udp dport 547 accept (DHCPv6)
//	    icmpv6 type 133-137 ip6 hoplimit 255 accept          (neighbour discovery)
//	    icmpv6 type { 130-132, 143 } ip6 hoplimit 1 accept   (MLD)
//	    meta l4proto tcp counter reject with tcp reset
//	    counter reject with icmpx admin-prohibited
//	  }
//	}
//
// Hooked last at output, as the guard's chain is; a packet must pass
// both, an accept ending only its own chain. The direct sets' elements
// expire DirectTimeout after they were put in: every Apply puts them in
// again, so a dead agent's direct destinations go within DirectTimeout
// and only the entries (and the LAN) are left. The table stays when the
// process dies (the crash posture) and when Close isn't called; Close
// removes it, a fresh kill switch's Close a previous run's.
type KillSwitch struct {
	mu      sync.Mutex
	netns   int // the namespace's fd; -1 is the calling thread's
	applied *KillSwitchRules
	closed  bool
	capable bool
}

// errKillSwitchClosed: the kill switch was closed.
var errKillSwitchClosed = errors.New("firewall: the kill switch is closed")

// NewKillSwitch returns the kill switch of the calling thread's network
// namespace. Nothing changes until Apply or Close.
func NewKillSwitch() *KillSwitch { return &KillSwitch{netns: -1} }

// NewKillSwitchInNamespace returns the kill switch of the network
// namespace at path, without entering it.
func NewKillSwitchInNamespace(path string) (*KillSwitch, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("firewall: namespace %s: %w", path, err)
	}
	return &KillSwitch{netns: fd}, nil
}

// probe is the guard's: one dump of the inet tables, whose answer alone
// can make the kill switch unsupported.
func (k *KillSwitch) probe(c *nftables.Conn) error {
	if k.capable {
		return nil
	}
	_, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err == nil {
		k.capable = true
		return nil
	}
	if noNFTables(err) {
		return fmt.Errorf("%w: %w", ErrKillSwitchUnsupported, err)
	}
	return fmt.Errorf("firewall: nftables: %w", err)
}

// Apply puts r in place, replacing whatever the table held (a previous
// run's included) in one transaction: there is never a moment without
// it. Applying what is in place again only checks the table holds
// exactly that, and rebuilds it if not.
func (k *KillSwitch) Apply(ctx context.Context, r KillSwitchRules) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return errKillSwitchClosed
	}
	c, err := nftConn(k.netns)
	if err != nil {
		return err
	}
	if err := k.probe(c); err != nil {
		return err
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: KillSwitchTable}
	sets := killSwitchSets(table, r)
	if k.applied != nil && k.applied.Equal(r) && wholeTable(c, KillSwitchTable, killSwitchRules(r, 0, 0, 0, 0), wants(sets)...) {
		// Put the direct sets' elements in again, their timeouts anew.
		for _, s := range sets[2:] {
			c.FlushSet(s.set)
			if err := addElements(c, s.set, s.elems); err != nil {
				return err
			}
		}
		if err := c.Flush(); err != nil {
			return fmt.Errorf("firewall: renew the kill switch's direct destinations: %w", err)
		}
		return nil
	}
	k.applied = nil
	c.AddTable(table)
	c.DelTable(table)
	c.AddTable(table)
	for _, s := range sets {
		if err := c.AddSet(s.set, nil); err != nil {
			return fmt.Errorf("firewall: kill switch set: %w", err)
		}
		if err := addElements(c, s.set, s.elems); err != nil {
			return err
		}
	}
	accept := nftables.ChainPolicyAccept
	prio := guardPriority
	chain := c.AddChain(&nftables.Chain{
		Name: guardChain, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: &prio, Policy: &accept,
	})
	for _, exprs := range killSwitchRules(r, sets[0].set.ID, sets[1].set.ID, sets[2].set.ID, sets[3].set.ID) {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("firewall: apply the kill switch: %w", err)
	}
	k.applied = &r
	return nil
}

// Close removes the table, whichever run put it there, and lets go of
// the namespace. A failure leaves the table in place, and the kill switch
// open for another Close. On a kernel without nf_tables there is nothing
// to remove.
func (k *KillSwitch) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	c, err := nftConn(k.netns)
	if err == nil {
		err = k.probe(c)
		if err == nil {
			table := &nftables.Table{Family: nftables.TableFamilyINet, Name: KillSwitchTable}
			c.AddTable(table)
			c.DelTable(table)
			if err = c.Flush(); err != nil {
				err = fmt.Errorf("firewall: remove the kill switch: %w", err)
			}
		} else if errors.Is(err, ErrKillSwitchUnsupported) {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	k.closed, k.applied = true, nil
	if k.netns >= 0 {
		_ = unix.Close(k.netns)
	}
	return nil
}

// ksSet is one of the kill switch's sets and its elements.
type ksSet struct {
	set   *nftables.Set
	elems []nftables.SetElement
}

// killSwitchSets are the sets for r: allow4, allow6, then the expiring
// direct4 and direct6.
func killSwitchSets(table *nftables.Table, r KillSwitchRules) []ksSet {
	set := func(name string, key nftables.SetDatatype, expire bool) *nftables.Set {
		s := &nftables.Set{Table: table, Name: name, KeyType: key, Interval: true}
		if expire {
			s.HasTimeout, s.Timeout = true, DirectTimeout
		}
		return s
	}
	return []ksSet{
		{set(killSwitchSet4, nftables.TypeIPAddr, false), intervals(ranges(r.Allow, false))},
		{set(killSwitchSet6, nftables.TypeIP6Addr, false), intervals(ranges(r.Allow, true))},
		{set(directSet4, nftables.TypeIPAddr, true), intervals(ranges(r.Direct, false))},
		{set(directSet6, nftables.TypeIP6Addr, true), intervals(ranges(r.Direct, true))},
	}
}

// wants are sets as wholeTable checks them.
func wants(sets []ksSet) []wantSet {
	out := make([]wantSet, len(sets))
	for i, s := range sets {
		out[i] = wantSet{s.set.Name, s.set.KeyType, s.elems}
	}
	return out
}

// addElements adds elems to set in messages of elementsPerMessage.
func addElements(c *nftables.Conn, set *nftables.Set, elems []nftables.SetElement) error {
	for len(elems) > 0 {
		n := min(len(elems), elementsPerMessage)
		if err := c.SetAddElements(set, elems[:n]); err != nil {
			return fmt.Errorf("firewall: kill switch set %s: %w", set.Name, err)
		}
		elems = elems[n:]
	}
	return nil
}

// ranges are s's ranges of one family.
func ranges(s *lists.Set, v6 bool) []lists.Range {
	var out []lists.Range
	for _, rg := range s.Ranges() {
		if rg.First.Is6() == v6 {
			out = append(out, rg)
		}
	}
	return out
}

// killSwitchRules are the output chain's rules, in order (see
// KillSwitch), looking the sets up by name and batch id.
func killSwitchRules(r KillSwitchRules, set4, set6, direct4, direct6 uint32) [][]expr.Any {
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	rules := [][]expr.Any{append(oifname("lo"), accept)}
	if r.TUN != "" {
		rules = append(rules, append(oifname(r.TUN), accept))
	}
	if r.Mark != 0 {
		rules = append(rules, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, r.Mark)},
			accept,
		})
	}
	return append(rules,
		append(nfproto(unix.NFPROTO_IPV4),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: killSwitchSet4, SetID: set4},
			accept),
		append(nfproto(unix.NFPROTO_IPV6),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: killSwitchSet6, SetID: set6},
			accept),
		append(nfproto(unix.NFPROTO_IPV4),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: directSet4, SetID: direct4},
			accept),
		append(nfproto(unix.NFPROTO_IPV6),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: directSet6, SetID: direct6},
			accept),
		append(udpPorts(unix.NFPROTO_IPV4, 68, 67), accept),
		append(udpPorts(unix.NFPROTO_IPV6, 546, 547), accept),
		append(append(icmpv6Type(), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{133}, ToData: []byte{137}}), hopLimit(255, accept)...),
		append(append(icmpv6Type(), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{130}, ToData: []byte{132}}), hopLimit(1, accept)...),
		append(append(icmpv6Type(), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{143}}), hopLimit(1, accept)...),
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Counter{},
			&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
		},
		[]expr.Any{
			&expr.Counter{},
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
		},
	)
}

// nfproto is "meta nfproto == family".
func nfproto(family byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
	}
}

// udpPorts is "meta nfproto == family udp sport == sport udp dport ==
// dport".
func udpPorts(family byte, sport, dport uint16) []expr.Any {
	return append(nfproto(family),
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, sport)},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, dport)},
	)
}
