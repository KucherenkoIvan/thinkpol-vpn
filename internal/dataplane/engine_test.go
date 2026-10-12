package dataplane_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const wait = 10 * time.Second

// fastPaths are path timings six times faster than the defaults. A link
// is dead after a second without proof: a busy machine can hold a probe up
// for hundreds of milliseconds, and a link closed for that drops what is
// sent meanwhile, a WireGuard handshake included, which is only retried
// after WireGuard's 5 s.
var fastPaths = path.Options{
	ProbeInterval: 300 * time.Millisecond,
	DeadAfter:     time.Second,
	RedialMin:     10 * time.Millisecond,
	RedialMax:     100 * time.Millisecond,
}

var (
	testSpace = transport.SpaceID{0x5a}
	space4    = netip.MustParsePrefix("100.64.0.0/16")
	space6    = netip.MustParsePrefix("fd00:1:2::/48")
)

// node is one node of a test space: its keys, its overlay addresses and,
// once started, its engine on a virtual TUN with a stack that answers
// pings.
type node struct {
	name   string
	id     netmap.NodeID
	key    netmap.WireGuardPrivateKey
	v4, v6 netip.Addr
	listen netip.AddrPort // zero for a node that only dials

	section netmap.Section
	blobs   func(netmap.BlobRef) ([]byte, bool) // for EngineConfig.Blobs
	forward bool                                // for EngineConfig.Forward
	routes  dataplane.RouteTable                // for EngineConfig.RouteTable
	standIn func(netmap.BlobKind, string) (netmap.BlobRef, []byte, bool)
	dns     interface{ Update(dns.Config) } // for EngineConfig.DNS
	engine  *dataplane.Engine
	stack   *stack
}

func newSpaceNode(name string, n byte, listen string) *node {
	nd := &node{
		name: name, id: netmap.NodeID{0, 0, 0, 0, 0, 0, 0, n}, key: netmap.GenerateWireGuardKey(),
		v4: netip.AddrFrom4([4]byte{100, 64, 0, n}),
		v6: netip.MustParseAddr(fmt.Sprintf("fd00:1:2::%d", n)),
	}
	if listen != "" {
		nd.listen = netip.MustParseAddrPort(listen)
	}
	nd.section.Node = netmap.NodeSettings{ID: nd.id, IPv4: nd.v4, IPv6: nd.v6, IPv4Network: space4, IPv6Network: space6}
	if nd.listen.IsValid() {
		nd.section.Node.Listeners = []netmap.Listener{{Transport: memory.Name, Address: nd.listen}}
	}
	return nd
}

func secret(from, to *node) []byte { return []byte(from.name + ">" + to.name) }

// link makes from dial to, and to accept it.
func link(from, to *node) {
	from.section.Links = append(from.section.Links, netmap.Link{Peer: to.id, Endpoints: []netmap.Endpoint{{
		Transport: memory.Name, Address: to.listen, Credential: secret(from, to),
	}}})
	to.section.Inbound = append(to.section.Inbound, netmap.InboundLink{
		Peer: from.id, Transport: memory.Name, Credential: secret(from, to),
	})
}

// peer makes to a WireGuard peer of from, reached through firstHops.
func peer(from, to *node, firstHops ...*node) {
	p := netmap.Peer{ID: to.id, WireGuardKey: to.key.Public(), Addresses: []netip.Addr{to.v4, to.v6}}
	for _, h := range firstHops {
		p.Paths = append(p.Paths, netmap.Path{FirstHop: h.id})
	}
	from.section.Peers = append(from.section.Peers, p)
}

// route makes relay forward packets for dst to next.
func route(relay, dst, next *node) {
	relay.section.Routes = append(relay.section.Routes, netmap.Route{Destination: dst.id, NextHops: []netmap.NodeID{next.id}})
}

// start runs the node's engine on net and applies its section.
func (nd *node) start(t *testing.T, net *memory.Network) {
	t.Helper()
	reg, err := transport.NewRegistry(net)
	if err != nil {
		t.Fatal(err)
	}
	ch := tuntest.NewChannelTUN()
	e, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID: nd.id, Space: testSpace, WireGuardKey: nd.key, Registry: reg, TUN: ch.TUN(), Path: fastPaths, Blobs: nd.blobs, StandIn: nd.standIn, DNS: nd.dns,
		Forward:    nd.forward,
		RouteTable: nd.routes,
	})
	if err != nil {
		t.Fatal(err)
	}
	nd.engine = e
	nd.stack = newStack(t, ch)
	if nd.listen.IsValid() {
		l, err := net.Listen(context.Background(), transport.ListenConfig{Address: nd.listen.String(), Peers: e.Inbound(memory.Name)})
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = e.Serve(memory.Name, l)
		}()
		t.Cleanup(func() { _ = l.Close(); <-served })
	}
	t.Cleanup(func() { _ = e.Close() })
	nd.apply(t)
}

func (nd *node) apply(t *testing.T) {
	t.Helper()
	if err := nd.engine.Apply(context.Background(), nd.section); err != nil {
		t.Fatal(err)
	}
}

// stack stands in for a node's IP stack behind its TUN: it answers pings
// and hands everything else to the test.
type stack struct {
	tun  *tuntest.ChannelTUN
	got  chan packettest.Packet
	done chan struct{}
}

func newStack(t *testing.T, ch *tuntest.ChannelTUN) *stack {
	s := &stack{tun: ch, got: make(chan packettest.Packet, 256), done: make(chan struct{})}
	t.Cleanup(func() { close(s.done) })
	go func() {
		for {
			select {
			case b := <-ch.Inbound:
				if reply, ok := packettest.Reply(b); ok {
					s.send(reply)
				} else if p, ok := packettest.Parse(b); ok {
					select {
					case s.got <- p:
					default:
					}
				}
			case <-s.done:
				return
			}
		}
	}()
	return s
}

func (s *stack) send(b []byte) bool {
	select {
	case s.tun.Outbound <- b:
		return true
	case <-s.done:
		return false
	}
}

// ping pings to's address of the family of dst from from until a reply
// comes back.
func ping(t *testing.T, from *node, dst netip.Addr) {
	t.Helper()
	if !tryPing(from, dst, wait) {
		t.Fatalf("%s: no reply from %s", from.name, dst)
	}
}

var pingID atomic.Uint32

func tryPing(from *node, dst netip.Addr, timeout time.Duration) bool {
	id := uint16(pingID.Add(1))
	src := from.v4
	if dst.Is6() {
		src = from.v6
	}
	deadline := time.After(timeout)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for seq := uint16(1); ; seq++ {
		if !from.stack.send(packettest.Echo(src, dst, id, seq, []byte("ping"))) {
			return false
		}
		for wait := true; wait; {
			select {
			case p := <-from.stack.got:
				if p.Src == dst && packettest.IsEchoReply(p, id, seq) {
					return true
				}
			case <-tick.C:
				wait = false
			case <-deadline:
				return false
			}
		}
	}
}

// sendUDP sends a datagram from one node to another and waits for it.
func sendUDP(t *testing.T, from, to *node, v6 bool) {
	t.Helper()
	src, dst := netip.AddrPortFrom(from.v4, 4000), netip.AddrPortFrom(to.v4, 5000)
	if v6 {
		src, dst = netip.AddrPortFrom(from.v6, 4000), netip.AddrPortFrom(to.v6, 5000)
	}
	payload := []byte("datagram from " + from.name)
	from.stack.send(packettest.UDPDatagram(src, dst, payload))
	deadline := time.After(wait)
	for {
		select {
		case p := <-to.stack.got:
			if s, d, data, ok := packettest.UDPData(p); ok && s == src && d == dst && bytes.Equal(data, payload) {
				return
			}
		case <-deadline:
			t.Fatalf("no datagram %s → %s", src, dst)
		}
	}
}

// m0 is M0's acceptance topology: device-a and device-b dial server-1,
// which relays between them; every node is every other's WireGuard peer.
func m0() (a, s, b *node) {
	a = newSpaceNode("device-a", 1, "")
	s = newSpaceNode("server-1", 2, "192.0.2.2:4500")
	b = newSpaceNode("device-b", 3, "")
	link(a, s)
	link(b, s)
	route(s, a, a)
	route(s, b, b)
	peer(a, s, s)
	peer(a, b, s)
	peer(b, s, s)
	peer(b, a, s)
	peer(s, a, a)
	peer(s, b, b)
	return a, s, b
}

// M0 in process: device ↔ server directly and device ↔ device through the
// server as relay, over IPv4 and IPv6, ping and UDP, on a datagram and a
// stream transport.
func TestDevicesReachEachOtherDirectlyAndThroughARelay(t *testing.T) {
	for _, sem := range []memory.Semantics{memory.Datagram, memory.Stream} {
		t.Run(sem.String(), func(t *testing.T) {
			t.Parallel()
			net := memory.NewNetwork(sem)
			a, s, b := m0()
			for _, nd := range []*node{s, a, b} {
				nd.start(t, net)
			}
			for _, pair := range [][2]*node{{a, s}, {s, a}, {a, b}, {b, a}, {b, s}} {
				ping(t, pair[0], pair[1].v4)
				ping(t, pair[0], pair[1].v6)
			}
			for _, v6 := range []bool{false, true} {
				sendUDP(t, a, b, v6)
				sendUDP(t, b, a, v6)
			}

			st := a.engine.Status()
			if st.MTU != dataplane.DefaultLinkMTU-48-path.HeaderSize-32 || !st.IPv6 || len(st.Skipped) != 0 {
				t.Fatalf("status %+v", st)
			}
			if len(st.Peers) != 2 || st.Peers[1].ID != b.id || st.Peers[1].FirstHop != s.id || st.Peers[1].Device != dataplane.OverlayDevice || st.Peers[1].LastHandshake.IsZero() {
				t.Fatalf("device-a's peers %+v, want device-b through server-1 with a handshake", st.Peers)
			}
			if c := s.engine.Status().Path; c.Forwarded == 0 {
				t.Fatalf("server-1 relayed nothing: %+v", c)
			}
		})
	}
}

// A map update that leaves a peer as it was keeps its WireGuard session;
// a peer dropped from the map is unreachable.
func TestReapplyKeepsSessionsAndDropsRemovedPeers(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	ping(t, a, b.v4)
	handshake := func() time.Time {
		for _, p := range a.engine.Status().Peers {
			if p.ID == b.id {
				return p.LastHandshake
			}
		}
		t.Fatal("device-b is not a peer of device-a")
		return time.Time{}
	}
	before := handshake()
	a.apply(t)
	ping(t, a, b.v6)
	if after := handshake(); !after.Equal(before) {
		t.Fatalf("handshake at %v, was %v: re-applying the map restarted the session", after, before)
	}

	a.section.Peers = a.section.Peers[:1] // server-1 only
	a.apply(t)
	if tryPing(a, b.v4, 500*time.Millisecond) {
		t.Fatal("device-b answered after leaving device-a's map")
	}
	ping(t, a, s.v4)
	if c := a.engine.Status().Router; c.NoRoute == 0 {
		t.Fatalf("router counters %+v: the pings to device-b should have had no route", c)
	}
}

// Links whose shaping leaves less than IPv6's minimum MTU: the overlay
// carries IPv4 only, and says so.
func TestIPv6IsOffBelowItsMinimumMTU(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram, memory.AcceptShaping())
	a, s, _ := m0()
	shaping, err := transport.Shaping{Padding: transport.Buckets(1000, 8000)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a.section.Links[0].Endpoints[0].Shaping = shaping
	s.section.Inbound[0].Shaping = shaping
	for _, nd := range []*node{s, a} {
		nd.start(t, net)
	}
	st := a.engine.Status()
	if want := 1000 - path.HeaderSize - 32; st.MTU != want || st.IPv6 || !strings.Contains(st.IPv6Off, "1280") {
		t.Fatalf("status %+v, want MTU %d without IPv6", st, want)
	}
	ping(t, a, s.v4)
	// Even with a rule sending all IPv6 to the overlay device, the
	// space's IPv6 network goes by peers, and no peer has an address there.
	dataplane.RouteDefaultsToOverlayForTest(a.engine)
	a.apply(t)
	before := a.engine.Status().Router
	if tryPing(a, s.v6, 300*time.Millisecond) {
		t.Fatal("IPv6 crossed an overlay that doesn't carry it")
	}
	if after := a.engine.Status().Router; after.NoRoute == before.NoRoute || after.Routed != before.Routed {
		t.Fatalf("router %+v, was %+v: the pings should have had no route", after, before)
	}
	for _, p := range st.Peers {
		for _, addr := range p.Addresses {
			if addr.Is6() {
				t.Fatalf("peer %s has IPv6 address %s on an IPv4-only overlay", p.ID, addr)
			}
		}
	}
}

func TestApplyRefusesAnotherNodesSection(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	a.start(t, net)
	if err := a.engine.Apply(context.Background(), s.section); err == nil {
		t.Fatal("applied server-1's section on device-a")
	}
}

// Status quotes nothing from the map: no endpoint addresses, no
// credentials, whatever was skipped.
func TestStatusQuotesNothingFromTheMap(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	a.section.Links[0].Endpoints = append(a.section.Links[0].Endpoints,
		netmap.Endpoint{Transport: memory.Name, Address: netip.MustParseAddrPort("192.0.2.7:0"), Credential: []byte("secret-7")},
		netmap.Endpoint{Transport: "carrier-pigeon", Address: netip.MustParseAddrPort("192.0.2.8:4500"), Credential: []byte("secret-8")})
	a.section.Inbound = append(a.section.Inbound, netmap.InboundLink{Peer: b.id, Transport: "carrier-pigeon", Credential: []byte("secret-9")})
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	ping(t, a, b.v4)
	st := a.engine.Status()
	if len(st.Skipped) != 3 || len(st.Neighbors) == 0 || len(st.Egresses) != 1 || st.Peers[1].TxBytes == 0 {
		t.Fatalf("status %+v", st)
	}
	text := fmt.Sprintf("%v %+v %#v", st, st, st)
	for _, secret := range []string{"192.0.2.", "carrier-pigeon", "secret-", "device-a>"} {
		if strings.Contains(text, secret) {
			t.Fatalf("status quotes %q from the map:\n%s", secret, text)
		}
	}
}

// A section that drops a peer takes it out of WireGuard, even when the same
// section holds a link the node can't use: device-b's handshakes no longer
// reach device-a's stack.
func TestRevocationIsNotHeldBackByABadLink(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram, memory.AcceptShaping())
	a, s, b := m0()
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	ping(t, b, a.v4)

	tiny, err := transport.Shaping{Padding: transport.Buckets(400, 8000)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a.section.Peers = a.section.Peers[:1] // server-1 only
	a.section.Links = append(a.section.Links, netmap.Link{Peer: b.id, Endpoints: []netmap.Endpoint{{
		Transport: memory.Name, Address: netip.MustParseAddrPort("192.0.2.3:4500"), Credential: []byte("tiny"), Shaping: tiny,
	}}})
	a.apply(t)
	st := a.engine.Status()
	if len(st.Peers) != 1 || st.Peers[0].ID != s.id || st.MTU != 1402 {
		t.Fatalf("status %+v, want server-1 alone, at the good link's MTU", st)
	}
	if !slices.Contains(st.Skipped, dataplane.Skip{Node: b.id, What: dataplane.ItemLink, Reason: dataplane.ReasonMTUTooSmall}) {
		t.Fatalf("skipped %v, want the tiny link", st.Skipped)
	}
	assertCutOff(t, b, a)
}

// A section that can't run at all (no IPv4 address) still takes away the
// peers it drops, and says which step failed.
func TestASectionThatCannotRunStillRevokes(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	ping(t, b, a.v4)
	broken := a.section
	broken.Node.IPv4 = netip.Addr{}
	broken.Peers = broken.Peers[:1]
	if err := a.engine.Apply(context.Background(), broken); err == nil {
		t.Fatal("applied a section without an IPv4 address")
	}
	if st := a.engine.Status(); st.LastApplyError != dataplane.StepSection || len(st.Peers) != 1 || st.MTU != 1402 {
		t.Fatalf("status %+v", st)
	}
	assertCutOff(t, b, a)
	ping(t, a, s.v4) // what stays keeps working
	a.apply(t)       // the good section again
	if st := a.engine.Status(); st.LastApplyError != "" || len(st.Peers) != 2 {
		t.Fatalf("status after re-applying %+v", st)
	}
	// device-b still holds its old session, which device-a forgot; a
	// handshake from device-a renews it (device-b's own comes after
	// WireGuard's 15 s).
	ping(t, a, b.v4)
	ping(t, b, a.v4)
}

// assertCutOff checks that from's pings no longer reach to's stack at all:
// to's WireGuard drops them, not just its router the replies.
func assertCutOff(t *testing.T, from, to *node) {
	t.Helper()
	before := to.engine.Status().Router.Delivered
	if tryPing(from, to.v4, time.Second) {
		t.Fatalf("%s still answers %s", to.name, from.name)
	}
	if after := to.engine.Status().Router.Delivered; after != before {
		t.Fatalf("%s's WireGuard delivered %d packets from %s after it was removed", to.name, after-before, from.name)
	}
}

// A peer moves between WireGuard devices in one Apply, as an exit moving
// into a chain's device will, and keeps working; a device without peers
// goes away.
func TestAPeerMovesBetweenDevices(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, b := m0()
	for _, nd := range []*node{s, a, b} {
		nd.start(t, net)
	}
	ping(t, a, b.v4)
	dataplane.PutPeerOnDeviceForTest(a.engine, b.id, "chain-x")
	a.apply(t)
	st := a.engine.Status()
	if len(st.Egresses) != 2 || len(st.Peers) != 2 || st.Peers[1].Device != "chain-x" || st.Peers[0].Device != dataplane.OverlayDevice {
		t.Fatalf("status %+v", st)
	}
	ping(t, a, b.v4)
	ping(t, b, a.v6)
	ping(t, a, s.v6)
	if eg := a.engine.Status().Egresses; eg[0].Name != "chain-x" || eg[0].Routed == 0 {
		t.Fatalf("egresses %+v: nothing went through chain-x", eg)
	}

	dataplane.PutPeerOnDeviceForTest(a.engine, netmap.NodeID{}, "")
	a.apply(t)
	if st := a.engine.Status(); len(st.Egresses) != 1 || st.Peers[1].Device != dataplane.OverlayDevice {
		t.Fatalf("status %+v", st)
	}
	ping(t, a, b.v4)
}

// A server with ingress off serves other servers only: a device holding a
// valid credential for it is refused, while the server still takes relayed
// traffic from another server. Turning ingress on lets the same device in.
func TestIngressOffServesOnlyServers(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a := newSpaceNode("device-a", 1, "")
	entry := newSpaceNode("entry", 2, "192.0.2.2:4500")
	exit := newSpaceNode("exit", 3, "192.0.2.3:4500")
	b := newSpaceNode("device-b", 4, "")
	kinds := map[*node]netmap.NodeKind{a: netmap.NodeDevice, b: netmap.NodeDevice, entry: netmap.NodeServer, exit: netmap.NodeServer}
	linkKinds := func(from, to *node) {
		link(from, to)
		to.section.Inbound[len(to.section.Inbound)-1].PeerKind = kinds[from]
	}
	for nd, k := range kinds {
		nd.section.Node.Kind = k
	}
	entry.section.Node.AllowIngress = true

	linkKinds(a, exit) // what a map builder must never write, with a credential that works
	peer(a, exit, exit)
	peer(exit, a, a)
	route(exit, a, a)

	linkKinds(b, entry)
	linkKinds(entry, exit)
	peer(b, exit, entry)
	peer(exit, b, entry)
	route(entry, exit, exit)
	route(entry, b, b)
	route(exit, b, entry)

	for _, nd := range []*node{exit, entry, a, b} {
		nd.start(t, net)
	}
	ping(t, b, exit.v4)
	if tryPing(a, exit.v4, time.Second) {
		t.Fatal("device-a reached the ingress-off server directly")
	}
	want := dataplane.Skip{Node: a.id, What: dataplane.ItemInbound, Reason: dataplane.ReasonIngressOff}
	if st := exit.engine.Status(); !slices.Contains(st.Skipped, want) {
		t.Fatalf("exit skipped %v, want %v", st.Skipped, want)
	}

	exit.section.Node.AllowIngress = true
	exit.apply(t)
	ping(t, a, exit.v4)
}
