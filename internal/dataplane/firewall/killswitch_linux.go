//go:build linux && !android

package firewall

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The kill switch's nftables table: owned by its name, apart from the
// guard's, so a successor finds what a crashed or stopped run left.
const (
	KillSwitchTable = "thinkpol-killswitch"
	forwardChain    = "forward"
	killSwitchSet4  = "allow4"
	killSwitchSet6  = "allow6"
	directSet4      = "direct4"
	directSet6      = "direct6"
	noDNSSet4       = "nodns4"
	noDNSSet6       = "nodns6"
)

// ksSetIDs are the batch ids of the kill switch's sets, in
// killSwitchSets' order; zero when only compared by name.
type ksSetIDs [6]uint32

// KillSwitch keeps everything but KillSwitchRules from leaving the
// device, both families, with one nftables table in a network namespace:
//
//	table inet thinkpol-killswitch {
//	  set allow4 { type ipv4_addr; flags interval; elements = <Allow's IPv4> }
//	  set allow6 { type ipv6_addr; flags interval; elements = <Allow's IPv6> }
//	  set direct4 { type ipv4_addr; flags interval,timeout; timeout 30s; elements = <Direct's IPv4> }
//	  set direct6 { type ipv6_addr; flags interval,timeout; timeout 30s; elements = <Direct's IPv6> }
//	  set nodns4 { type ipv4_addr; flags interval; elements = <NoDNS's IPv4> }
//	  set nodns6 { type ipv6_addr; flags interval; elements = <NoDNS's IPv6> }
//	  chain output { type filter hook output priority 2147483647; policy accept;
//	    oifname "lo" accept
//	    oifname <TUN> accept                                 (connected only)
//	    meta mark <Mark> accept
//	    meta nfproto ipv4 ip daddr @nodns4 udp dport 53 counter reject with icmpx admin-prohibited
//	    meta nfproto ipv4 ip daddr @nodns4 tcp dport 53 counter reject with tcp reset
//	    meta nfproto ipv4 ip daddr @nodns4 tcp dport 853 counter reject with tcp reset
//	    meta nfproto ipv4 ip daddr @nodns4 udp dport 853 counter reject with icmpx admin-prohibited
//	    (the same four for ip6 daddr @nodns6)
//	    meta nfproto ipv4 ip daddr @allow4 accept
//	    meta nfproto ipv6 ip6 daddr @allow6 accept
//	    meta nfproto ipv4 ip daddr @direct4 accept
//	    meta nfproto ipv6 ip6 daddr @direct6 accept
//	    meta nfproto ipv4 udp sport 68 udp dport 67 accept   (DHCPv4)
//	    meta nfproto ipv6 udp sport 546 udp dport 547 ip6 daddr ff02::1:2 accept   (DHCPv6)
//	    meta nfproto ipv6 udp sport 546 udp dport 547 ip6 daddr fe80::/10 accept
//	    icmpv6 type 133-137 ip6 hoplimit 255 accept          (neighbour discovery)
//	    icmpv6 type { 130-132, 143 } ip6 hoplimit 1 accept   (MLD)
//	    meta l4proto tcp counter reject with tcp reset
//	    counter reject with icmpx admin-prohibited
//	  }
//	  chain forward { type filter hook forward priority 2147483647; policy accept;
//	    oifname <TUN> accept                                 (connected only)
//	    iifname <TUN> accept                                 (connected only)
//	    iifname <bridge> oifname <bridge> accept             (each bridge on its own: innerBridges)
//	    (the eight @nodns rules of output)
//	    meta nfproto ipv4 ip daddr @allow4 accept
//	    meta nfproto ipv6 ip6 daddr @allow6 accept
//	    meta nfproto ipv4 ip daddr @direct4 accept
//	    meta nfproto ipv6 ip6 daddr @direct6 accept
//	    ct direction reply meta nfproto ipv4 ip saddr @allow4 accept
//	    ct direction reply meta nfproto ipv6 ip6 saddr @allow6 accept
//	    ct direction reply meta nfproto ipv4 ip saddr @direct4 accept
//	    ct direction reply meta nfproto ipv6 ip6 saddr @direct6 accept
//	    meta l4proto tcp counter reject with tcp reset
//	    counter reject with icmpx admin-prohibited
//	  }
//	}
//
// Output and forward are both hooked last, as the guard's chain is; a
// packet must pass every table's chain, an accept ending only its own.
// The forward chain confines what the device routes for others
// (containers, VMs, a hotspot's clients), which never meets output: it
// lets it into and out of the TUN, and to the allowed and direct
// destinations; their replies pass by their source only in conntrack's
// reply direction, so a client can't make a packet to anywhere else pass
// by spoofing its source. ICMP errors from routers on the way to an
// allowed or direct destination aren't replies from it, and are refused
// (path MTU discovery of a forwarded client's direct flow included; its
// tunnelled flows come in by the TUN). A refusal goes back to the client
// by output, which lets it out only to an allowed address (the client's,
// with allow-LAN); otherwise it is refused in turn, and the client times
// out instead of failing at once. With br_netfilter (bridge-nf-call-
// iptables, as Docker up to 27 and Kubernetes set it) a frame bridged
// between two ports of one bridge (container to container on docker0)
// meets the forward hook too, the bridge both its in and out interface:
// it passes if the bridge is on its own (innerBridges: only veth and tap
// ports, no default or gatewayed route out of it). A bridge that
// enslaves the uplink, or carries the default route, isn't: a VM's frame
// bridged from its tap to eth0 in the uplink's br0 meets the hook with
// br0 as both too, and would leave for the internet, so such a bridge
// falls through to the refusals (its VMs then reach only what the sets
// allow, the LAN with allow-LAN, never its DNS while down). nftables'
// inet family has no bridge-port key (meta ibrname is the bridge
// family's), and an xt physdev match would make nft unable to list the
// table, so the bridges are named one by one, as listed at each Apply:
// a bridge made, or a port or route changed, since counts from the
// next one (the agent's re-apply). A packet routed back out of the
// bridge it came in by passes as well (only a bridge on its own, which
// routes nowhere beyond its link). Not postrouting:
// reject is refused there (input, forward and output only), and output
// already has what the device sends itself. The direct sets' elements
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
	// listBridges is innerBridges when nil (tests fail it).
	listBridges func(netns int) ([]string, error)
}

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
// exactly that, and rebuilds it if not. When the bridges can't be
// listed, r goes in with no bridge passing and Apply returns the
// listing's error: the next Apply lists them again.
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
	list := innerBridges
	if k.listBridges != nil {
		list = k.listBridges
	}
	// Unlisted, the rest still goes in, with no bridge passing: bridged
	// frames are refused, nothing else is open meanwhile. The error is
	// still Apply's, so the agent reports it and applies again.
	bridges, listErr := list(k.netns)
	if listErr != nil {
		bridges = nil
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: KillSwitchTable}
	sets := killSwitchSets(table, r)
	if k.applied != nil && k.applied.Equal(r) && wholeTable(c, KillSwitchTable, killSwitchChains(r, ksSetIDs{}, bridges), wants(sets)...) {
		// Put the direct sets' elements in again, their timeouts anew.
		for _, s := range sets[2:4] {
			c.FlushSet(s.set)
			if err := addElements(c, s.set, s.elems); err != nil {
				return err
			}
		}
		if err := c.Flush(); err != nil {
			return fmt.Errorf("firewall: renew the kill switch's direct destinations: %w", err)
		}
		return listErr
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
	prio := lastPriority
	var ids ksSetIDs
	for i, s := range sets {
		ids[i] = s.set.ID
	}
	for _, w := range killSwitchChains(r, ids, bridges) {
		chain := c.AddChain(&nftables.Chain{
			Name: w.name, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: &w.hook, Priority: &prio, Policy: &accept,
		})
		for _, exprs := range w.rules {
			c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("firewall: apply the kill switch: %w", err)
	}
	k.applied = &r
	return listErr
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

// killSwitchSets are the sets for r: allow4, allow6, the expiring
// direct4 and direct6, then nodns4 and nodns6.
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
		{set(noDNSSet4, nftables.TypeIPAddr, false), intervals(ranges(r.NoDNS, false))},
		{set(noDNSSet6, nftables.TypeIP6Addr, false), intervals(ranges(r.NoDNS, true))},
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

// killSwitchChains are the table's chains for r (see KillSwitch), looking
// the sets up by name and batch id, with bridges the namespace's bridges.
func killSwitchChains(r KillSwitchRules, ids ksSetIDs, bridges []string) []wantChain {
	return []wantChain{
		{outputChain, *nftables.ChainHookOutput, outputRules(r, ids)},
		{forwardChain, *nftables.ChainHookForward, forwardRules(r, ids, bridges)},
	}
}

// innerBridges are the bridges of the namespace (netns, -1 the calling
// thread's) whose frames may pass bridged within them, sorted: those
// whose every port is a veth or a tap (containers, VMs) and out of which
// no route of either family, in any table, is a default route or goes by
// a gateway. A bridge with any other port (the uplink enslaved, a Wi-Fi
// interface, a VLAN, a bond, a VXLAN) or that routes beyond its link
// (the host's uplink, an entry reached through it) isn't one: what it
// bridges falls through to the refusals. A gatewayed or default route
// that names no interface (a nexthop object) can't be placed: then none
// is.
func innerBridges(netns int) ([]string, error) {
	var h *netlink.Handle
	var err error
	if netns >= 0 {
		h, err = netlink.NewHandleAt(vnetns.NsHandle(netns), unix.NETLINK_ROUTE)
	} else {
		h, err = netlink.NewHandle(unix.NETLINK_ROUTE)
	}
	if err != nil {
		return nil, fmt.Errorf("firewall: list the bridges: %w", err)
	}
	defer h.Close()
	for range 3 {
		var links []netlink.Link
		var routes []netlink.Route
		links, err = h.LinkList()
		if err == nil {
			routes, err = h.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		}
		if errors.Is(err, netlink.ErrDumpInterrupted) {
			continue // the links or routes changed during the dump
		}
		if err != nil {
			break
		}
		return bridgesOnTheirOwn(links, routes), nil
	}
	return nil, fmt.Errorf("firewall: list the bridges: %w", err)
}

// bridgesOnTheirOwn are innerBridges of links and routes.
func bridgesOnTheirOwn(links []netlink.Link, routes []netlink.Route) []string {
	bridges := map[int]string{}
	for _, l := range links {
		if l.Type() == "bridge" {
			bridges[l.Attrs().Index] = l.Attrs().Name
		}
	}
	for _, l := range links {
		if m := l.Attrs().MasterIndex; m != 0 && l.Type() != "veth" && l.Type() != "tuntap" {
			delete(bridges, m)
		}
	}
	for _, r := range routes {
		if r.Type != unix.RTN_UNICAST {
			continue // local, broadcast, unreachable, blackhole: never out of a bridge
		}
		gateway := r.Gw != nil || r.Via != nil
		out := []int{r.LinkIndex}
		for _, nh := range r.MultiPath {
			gateway = gateway || nh.Gw != nil || nh.Via != nil
			out = append(out, nh.LinkIndex)
		}
		if !gateway && r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue // on-link, not a default route
			}
		}
		placed := false
		for _, i := range out {
			if i != 0 {
				placed = true
				delete(bridges, i)
			}
		}
		if !placed {
			return nil
		}
	}
	names := slices.Collect(maps.Values(bridges))
	slices.Sort(names)
	return names
}

// ksLookups are "<family> <load> @set accept" for allow4, allow6,
// direct4 and direct6, the address loaded by load(v6).
func ksLookups(ids ksSetIDs, load func(v6 bool) expr.Any) [][]expr.Any {
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	names := [4]string{killSwitchSet4, killSwitchSet6, directSet4, directSet6}
	out := make([][]expr.Any, 4)
	for i, name := range names {
		family := byte(unix.NFPROTO_IPV4)
		if i%2 == 1 {
			family = unix.NFPROTO_IPV6
		}
		out[i] = append(nfproto(family), load(i%2 == 1), &expr.Lookup{SourceRegister: 1, SetName: name, SetID: ids[i]}, accept)
	}
	return out
}

// daddr loads a packet's destination address.
func daddr(v6 bool) expr.Any {
	if v6 {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

// saddr loads a packet's source address.
func saddr(v6 bool) expr.Any {
	if v6 {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}
}

// refused are the chains' last two rules: TCP reset, the rest an ICMP
// "administratively prohibited".
func refused() [][]expr.Any {
	return [][]expr.Any{
		{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Counter{},
			&expr.Reject{Type: unix.NFT_REJECT_TCP_RST},
		},
		{
			&expr.Counter{},
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
		},
	}
}

// noDNS refuses DNS to the nodns sets: UDP to ports 53 and 853 (DNS over
// QUIC) with an ICMP error, TCP to ports 53 and 853 with a reset, both
// families.
func noDNS(ids ksSetIDs) [][]expr.Any {
	var rules [][]expr.Any
	for i, name := range []string{noDNSSet4, noDNSSet6} {
		family := byte(unix.NFPROTO_IPV4)
		if i == 1 {
			family = unix.NFPROTO_IPV6
		}
		for _, d := range []struct {
			proto byte
			port  uint16
		}{{unix.IPPROTO_UDP, 53}, {unix.IPPROTO_TCP, 53}, {unix.IPPROTO_TCP, 853}, {unix.IPPROTO_UDP, 853}} {
			reject := &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}
			if d.proto == unix.IPPROTO_TCP {
				reject = &expr.Reject{Type: unix.NFT_REJECT_TCP_RST}
			}
			rules = append(rules, append(nfproto(family),
				daddr(i == 1),
				&expr.Lookup{SourceRegister: 1, SetName: name, SetID: ids[4+i]},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{d.proto}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, d.port)},
				&expr.Counter{},
				reject,
			))
		}
	}
	return rules
}

// outputRules are the output chain's rules, in order.
func outputRules(r KillSwitchRules, ids ksSetIDs) [][]expr.Any {
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
	rules = append(rules, noDNS(ids)...)
	rules = append(rules, ksLookups(ids, daddr)...)
	rules = append(rules,
		append(udpPorts(unix.NFPROTO_IPV4, 68, 67), accept),
		append(udpPorts(unix.NFPROTO_IPV6, 546, 547), daddr(true),
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: allDHCPServers[:]}, accept),
		append(udpPorts(unix.NFPROTO_IPV6, 546, 547), daddr(true),
			&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: linkLocalFirst[:], ToData: linkLocalLast[:]}, accept),
		append(append(icmpv6Type(), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{133}, ToData: []byte{137}}), hopLimit(255, accept)...),
		append(append(icmpv6Type(), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{130}, ToData: []byte{132}}), hopLimit(1, accept)...),
		append(append(icmpv6Type(), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{143}}), hopLimit(1, accept)...),
	)
	return append(rules, refused()...)
}

// forwardRules are the forward chain's rules, in order.
func forwardRules(r KillSwitchRules, ids ksSetIDs, bridges []string) [][]expr.Any {
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	var rules [][]expr.Any
	if r.TUN != "" {
		rules = append(rules, append(oifname(r.TUN), accept), append(iifname(r.TUN), accept))
	}
	for _, b := range bridges {
		rules = append(rules, append(append(iifname(b), oifname(b)...), accept))
	}
	rules = append(rules, noDNS(ids)...)
	rules = append(rules, ksLookups(ids, daddr)...)
	// "ct direction reply": a reply of a flow someone else opened. (Not
	// "ct original ip daddr": nftables sends and reads that key's
	// direction as 4 bytes where the kernel dumps 1, so the table would
	// never read back whole.)
	for _, l := range ksLookups(ids, saddr) {
		rules = append(rules, append([]expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, // IP_CT_DIR_REPLY
		}, l...))
	}
	return append(rules, refused()...)
}

// DHCPv6's destinations: All_DHCP_Relay_Agents_and_Servers, and the
// link-local unicast range (fe80::/10) a server on the link answers from.
var (
	allDHCPServers = netip.MustParseAddr("ff02::1:2").As16()
	linkLocalFirst = netip.MustParseAddr("fe80::").As16()
	linkLocalLast  = netip.MustParseAddr("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff").As16()
)

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
