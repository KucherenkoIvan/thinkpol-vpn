//go:build linux && !android

package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The guard's nftables table: owned by its name, like the route table's
// routes by their protocol, so a successor finds what a crashed run left.
const (
	GuardTable = "thinkpol-guard"
	guardChain = "output"
	guardSet   = "exempt6"
)

// guardPriority hooks the chain after every other output chain
// (NF_IP6_PRI_LAST): a route chain that re-marks or reroutes a packet
// does so before the guard sees it, never after.
const guardPriority = nftables.ChainPriority(math.MaxInt32)

// IPv6Guard is routetable's Guard on Linux: it keeps IPv6 from leaving
// around the tunnel (routetable.Exempt) with one nftables table in a
// network namespace:
//
//	table inet thinkpol-guard {
//	  set exempt6 { type ipv6_addr; flags interval; elements = <Exempt.Ranges6> }
//	  chain output { type filter hook output priority 2147483647; policy accept;
//	    oifname "lo" accept
//	    oifname <TUN> accept
//	    meta nfproto != ipv6 accept
//	    meta mark <Mark> accept
//	    ip6 daddr @exempt6 accept
//	    icmpv6 type 133-137 ip6 hoplimit 255 accept          (neighbour discovery)
//	    icmpv6 type { 130-132, 143 } ip6 hoplimit 1 accept   (MLD)
//	    meta l4proto tcp counter reject with tcp reset
//	    counter reject with icmpx admin-prohibited
//	  }
//	}
//
// Refused, not dropped: an app learns at once (a reset, an ICMPv6 error
// to its own socket) and falls back to IPv4 or the tunnel. Neighbour
// discovery and MLD pass whatever their destination (a neighbour
// solicitation to a global address) only with the hop limit they must
// carry (255, 1), so they can't leave the link. Only locally generated
// traffic is guarded: forwarded traffic is never bound to an interface,
// and routing (rule 5301) keeps it in the tunnel. Exempt.Upstreams are
// left to Mark: the direct DNS upstream's sockets carry it here.
//
// The table stays when the process dies (a crash leaves IPv6 confined,
// as the route table's unreachable default does); the next start removes
// it (routetable.Clear with a fresh guard) or replaces it.
type IPv6Guard struct {
	mu      sync.Mutex
	netns   int // the namespace's fd; -1 is the calling thread's
	applied *routetable.Exempt
	closed  bool
}

var _ routetable.Guard = (*IPv6Guard)(nil)

// errClosed: the guard was closed.
var errClosed = errors.New("firewall: the IPv6 guard is closed")

// NewIPv6Guard returns the guard of the calling thread's network
// namespace. Nothing is in place until Apply; Close removes what is
// there, a crashed run's table included.
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

// sockbuf holds a batch with a country-sized set (about 40 bytes an
// element, two elements a range): the default socket buffers (~200 KiB)
// refuse one sendmsg that big, and overflow on the acks of a failing
// one. The watcher's socket gets it too, against bursts of events.
const sockbuf = 8 << 20

// elementsPerMessage keeps each message's element list, one netlink
// attribute, under its 64 KiB length limit (an IPv6 element takes up to
// 36 bytes): google/nftables doesn't check, and an overlong list arrives
// as garbage the kernel answers with ENOENT.
const elementsPerMessage = 1024

// forceBuffers sets c's socket buffers to sockbuf past the sysctl limits
// (SO_*BUFFORCE needs CAP_NET_ADMIN, which nftables needs anyway).
func forceBuffers(c *netlink.Conn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = errors.Join(
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sockbuf),
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, sockbuf))
	}); err != nil {
		return err
	}
	return serr
}

func (g *IPv6Guard) conn() (*nftables.Conn, error) {
	opts := []nftables.ConnOption{nftables.WithSockOptions(forceBuffers)}
	if g.netns >= 0 {
		opts = append(opts, nftables.WithNetNSFd(g.netns))
	}
	c, err := nftables.New(opts...)
	if err != nil {
		return nil, unsupported(fmt.Errorf("firewall: nftables: %w", err))
	}
	return c, nil
}

// unsupported marks err as routetable.ErrGuardUnsupported when it says
// the kernel has no nf_tables (no netfilter netlink, or no nftables
// subsystem behind it).
func unsupported(err error) error {
	if err == nil {
		return nil
	}
	for _, errno := range []unix.Errno{unix.EPROTONOSUPPORT, unix.EOPNOTSUPP, unix.EAFNOSUPPORT} {
		if errors.Is(err, errno) {
			return fmt.Errorf("%w: %w", routetable.ErrGuardUnsupported, err)
		}
	}
	return err
}

// Apply puts e in place, replacing whatever the table held in one
// transaction: there is never a moment without a guard. Applying what is
// in place again only checks the table is still whole (someone may have
// deleted it or its rules), and rebuilds it if not.
func (g *IPv6Guard) Apply(ctx context.Context, e routetable.Exempt) error {
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
	prio := guardPriority
	chain := c.AddChain(&nftables.Chain{
		Name: guardChain, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: &prio, Policy: &accept,
	})
	for _, exprs := range guardRules(e, set.Name, set.ID) {
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
	if err := c.Flush(); err != nil {
		return unsupported(fmt.Errorf("firewall: apply the IPv6 guard: %w", err))
	}
	g.applied = &e
	return nil
}

// whole reports whether the table holds e's chain, rules and set.
// (Elements deleted one by one go unnoticed: only a refusal can come of
// it, never a leak.)
func whole(c *nftables.Conn, e routetable.Exempt) bool {
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: GuardTable}
	if _, err := c.ListChain(table, guardChain); err != nil {
		return false
	}
	rules, err := c.GetRules(table, &nftables.Chain{Name: guardChain, Table: table})
	if err != nil || len(rules) != len(guardRules(e, guardSet, 0)) {
		return false
	}
	_, err = c.GetSetByName(table, guardSet)
	return err == nil
}

// Close removes the table and lets go of the namespace. A failure leaves
// the guard open, so Close can be tried again. On a kernel without
// nf_tables there is nothing to remove.
func (g *IPv6Guard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	c, err := g.conn()
	if err == nil {
		err = unsupported(removeGuard(c))
	}
	if err != nil && !errors.Is(err, routetable.ErrGuardUnsupported) {
		return err
	}
	g.closed, g.applied = true, nil
	if g.netns >= 0 {
		_ = unix.Close(g.netns)
	}
	return nil
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

// Watch signals, coalesced, when anything of the guard's table is
// deleted or a rule is added to it from outside (`nft flush ruleset`, a
// firewall service's reload, a rule inserted ahead of ours), and when
// events may have been lost (the socket overflowed). The guard's own
// Apply shows up too, and finds the table whole. The channel closes when
// ctx ends or the subscription breaks.
func (g *IPv6Guard) Watch(ctx context.Context) (<-chan struct{}, error) {
	g.mu.Lock()
	ns, closed := g.netns, g.closed
	g.mu.Unlock()
	if closed {
		return nil, errClosed
	}
	cfg := &netlink.Config{}
	if ns >= 0 {
		cfg.NetNS = ns
	}
	nl, err := netlink.Dial(unix.NETLINK_NETFILTER, cfg)
	if err != nil {
		return nil, unsupported(fmt.Errorf("firewall: watch: %w", err))
	}
	if err := errors.Join(forceBuffers(nl), nl.JoinGroup(unix.NFNLGRP_NFTABLES)); err != nil {
		_ = nl.Close()
		return nil, unsupported(fmt.Errorf("firewall: watch: %w", err))
	}
	out := make(chan struct{}, 1)
	signal := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = nl.Close() })
	go func() {
		defer close(out)
		defer stop()
		defer func() { _ = nl.Close() }()
		for {
			msgs, err := nl.Receive()
			switch {
			case ctx.Err() != nil:
				return
			case errors.Is(err, unix.ENOBUFS):
				signal() // something may have been lost
				continue
			case err != nil:
				return
			}
			for _, m := range msgs {
				if touchesGuard(m) {
					signal()
				}
			}
		}
	}()
	return out, nil
}

// touchesGuard says whether m, an nftables event, deletes something of
// the guard's table or adds a rule to it. Each of these messages starts
// with the family (nfgenmsg) and has the table's name as attribute 1.
func touchesGuard(m netlink.Message) bool {
	if m.Header.Type>>8 != unix.NFNL_SUBSYS_NFTABLES || len(m.Data) < 4 || m.Data[0] != unix.NFPROTO_INET {
		return false
	}
	switch m.Header.Type & 0xff {
	case unix.NFT_MSG_DELTABLE, unix.NFT_MSG_DELCHAIN, unix.NFT_MSG_DELRULE, unix.NFT_MSG_DELSET, unix.NFT_MSG_NEWRULE:
	default:
		return false
	}
	ad, err := netlink.NewAttributeDecoder(m.Data[4:])
	if err != nil {
		return false
	}
	for ad.Next() {
		if ad.Type() == 1 { // NFTA_{TABLE_NAME,CHAIN_TABLE,RULE_TABLE,SET_TABLE}
			return ad.String() == GuardTable
		}
	}
	return false
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

// guardRules are the output chain's rules, in order (see IPv6Guard),
// looking the set up by name and batch id.
func guardRules(e routetable.Exempt, setName string, setID uint32) [][]expr.Any {
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
			&expr.Lookup{SourceRegister: 1, SetName: setName, SetID: setID},
			accept,
		},
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

// hopLimit is "ip6 hoplimit == n", then the verdict.
func hopLimit(n byte, verdict expr.Any) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{n}},
		verdict,
	}
}
