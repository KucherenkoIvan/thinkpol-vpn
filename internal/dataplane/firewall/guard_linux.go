//go:build linux && !android

package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The guard's nftables table: owned by its name, like the route table's
// routes by their protocol, so a successor finds what a crashed run left.
const (
	GuardTable = "thinkpol-guard"
	guardChain = "output"
	guardSet   = "exempt6"
)

// IPv6Guard keeps IPv6 from leaving around the tunnel (Exempt) with one
// nftables table in a network namespace:
//
//	table inet thinkpol-guard {
//	  set exempt6 { type ipv6_addr; flags interval; elements = <Exempt.Ranges6> }
//	  chain output { type filter hook output priority filter; policy accept;
//	    oifname "lo" accept
//	    oifname <TUN> accept
//	    meta nfproto != ipv6 accept
//	    meta mark <Mark> accept
//	    ip6 daddr @exempt6 accept
//	    icmpv6 type 130-137 accept     (MLD, neighbour discovery)
//	    icmpv6 type 143 accept         (MLDv2 reports)
//	    meta l4proto tcp counter reject with tcp reset
//	    counter reject with icmpx admin-prohibited
//	  }
//	}
//
// Refused, not dropped: an app learns at once (a reset, an ICMPv6 error
// to its own socket) and falls back to IPv4 or the tunnel. Neighbour
// discovery passes whatever its target (a neighbour solicitation to a
// global address): it never leaves the link. Only output is guarded: a
// device forwards nothing of its own, and forwarded packets can't be
// bound to an interface, so routing keeps them in.
//
// The table stays when the process dies (a crash leaves IPv6 confined,
// as the route table's unreachable default does); the next start removes
// it (ClearIPv6Guard) or replaces it.
type IPv6Guard struct {
	mu      sync.Mutex
	netns   int // the namespace's fd; -1 is the calling thread's
	applied *Exempt
	closed  bool
}

// errClosed: the guard was closed.
var errClosed = errors.New("firewall: the IPv6 guard is closed")

// NewIPv6Guard returns the guard of the calling thread's network
// namespace. Nothing is in place until Apply.
func NewIPv6Guard() *IPv6Guard { return &IPv6Guard{netns: -1} }

// NewIPv6GuardInNamespace returns the guard of the network namespace at
// path (/run/netns/<name>, /proc/<pid>/ns/net), without entering it.
func NewIPv6GuardInNamespace(path string) (*IPv6Guard, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("firewall: namespace %s: %w", path, err)
	}
	return &IPv6Guard{netns: fd}, nil
}

// sndbuf holds a batch with a country-sized set (about 40 bytes an
// element, two elements a range); the default socket buffer (~200 KiB)
// refuses one sendmsg that big.
const sndbuf = 8 << 20

// elementsPerMessage keeps each message's element list, one netlink
// attribute, under its 64 KiB length limit (an IPv6 element takes up to
// 36 bytes): google/nftables doesn't check, and an overlong list arrives
// as garbage the kernel answers with ENOENT.
const elementsPerMessage = 1024

func (g *IPv6Guard) conn() (*nftables.Conn, error) {
	opts := []nftables.ConnOption{nftables.WithSockOptions(func(c *netlink.Conn) error {
		raw, err := c.SyscallConn()
		if err != nil {
			return err
		}
		var serr error
		if err := raw.Control(func(fd uintptr) {
			// SO_SNDBUFFORCE passes wmem_max; it needs CAP_NET_ADMIN,
			// which changing nftables needs anyway.
			serr = errors.Join(
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sndbuf),
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, sndbuf))
		}); err != nil {
			return err
		}
		return serr
	})}
	if g.netns >= 0 {
		opts = append(opts, nftables.WithNetNSFd(g.netns))
	}
	c, err := nftables.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("firewall: nftables: %w", err)
	}
	return c, nil
}

// Apply puts e in place, replacing whatever the table held in one
// transaction: there is never a moment without a guard. Applying what is
// in place again only checks the table is still whole (someone may have
// deleted it or its rules), and rebuilds it if not.
func (g *IPv6Guard) Apply(ctx context.Context, e Exempt) error {
	if e.TUN == "" {
		return errors.New("firewall: no TUN")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errClosed
	}
	c, err := g.conn()
	if err != nil {
		return err
	}
	if g.applied != nil && g.applied.Equal(e) && whole(c, e) {
		return nil
	}
	g.applied = nil
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: GuardTable}
	// Add-then-delete-then-add replaces the table atomically whether or
	// not it (or a crashed run's) was there.
	c.AddTable(table)
	c.DelTable(table)
	c.AddTable(table)
	set := &nftables.Set{Table: table, Name: guardSet, KeyType: nftables.TypeIP6Addr, Interval: true}
	if err := c.AddSet(set, nil); err != nil {
		return fmt.Errorf("firewall: guard set: %w", err)
	}
	elems := intervals(e.Ranges6())
	for len(elems) > 0 {
		n := min(len(elems), elementsPerMessage)
		if err := c.SetAddElements(set, elems[:n]); err != nil {
			return fmt.Errorf("firewall: guard set: %w", err)
		}
		elems = elems[n:]
	}
	accept := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name: guardChain, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &accept,
	})
	for _, exprs := range guardRules(e, set) {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("firewall: apply the IPv6 guard: %w", err)
	}
	g.applied = &e
	return nil
}

// whole reports whether the table holds e's chain, rules and set.
// (Elements deleted one by one go unnoticed: only a refusal can come of
// it, never a leak.)
func whole(c *nftables.Conn, e Exempt) bool {
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: GuardTable}
	if _, err := c.ListChain(table, guardChain); err != nil {
		return false
	}
	rules, err := c.GetRules(table, &nftables.Chain{Name: guardChain, Table: table})
	if err != nil || len(rules) != len(guardRules(e, &nftables.Set{Name: guardSet})) {
		return false
	}
	_, err = c.GetSetByName(table, guardSet)
	return err == nil
}

// Close removes the table and lets go of the namespace.
func (g *IPv6Guard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	c, err := g.conn()
	if err == nil {
		err = removeGuard(c)
	}
	g.applied = nil
	if g.netns >= 0 {
		_ = unix.Close(g.netns)
	}
	return err
}

// ClearIPv6Guard removes the table a previous run of this namespace left
// (a crash), if there is one.
func ClearIPv6Guard() error {
	c, err := NewIPv6Guard().conn()
	if err != nil {
		return err
	}
	return removeGuard(c)
}

func removeGuard(c *nftables.Conn) error {
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: GuardTable}
	c.AddTable(table)
	c.DelTable(table)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("firewall: remove the IPv6 guard: %w", err)
	}
	return nil
}

// intervals are ranges as an interval set's elements: each range's first
// address, and the address after its last flagged as an interval's end
// (none for a range up to the last address: an interval with no end runs
// to the top).
func intervals(ranges []lists.Range) []nftables.SetElement {
	out := make([]nftables.SetElement, 0, 2*len(ranges))
	for _, r := range ranges {
		out = append(out, nftables.SetElement{Key: r.First.AsSlice()})
		if next := r.Last.Next(); next.IsValid() {
			out = append(out, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return out
}

// guardRules are the output chain's rules, in order (see IPv6Guard).
func guardRules(e Exempt, set *nftables.Set) [][]expr.Any {
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	rules := [][]expr.Any{
		append(oifname("lo"), accept),
		append(oifname(e.TUN), accept),
		{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			accept,
		},
	}
	if e.Mark != 0 {
		rules = append(rules, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, e.Mark)},
			accept,
		})
	}
	rules = append(rules,
		[]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
			accept,
		},
		append(icmpv6Type(), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{130}, ToData: []byte{137}}, accept),
		append(icmpv6Type(), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{143}}, accept),
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
	return rules
}

// oifname is "oifname == name" (the whole name and its NUL, as nft
// compares an exact name).
func oifname(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(name), 0)},
	}
}

// icmpv6Type loads an ICMPv6 packet's type into register 1.
func icmpv6Type() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
	}
}
