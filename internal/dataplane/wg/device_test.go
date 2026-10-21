package wg_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/wg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const wait = 10 * time.Second

var fast = path.Options{
	ProbeInterval: 30 * time.Millisecond,
	DeadAfter:     150 * time.Millisecond,
	RedialMin:     10 * time.Millisecond,
	RedialMax:     100 * time.Millisecond,
}

func id(name string) path.NodeID {
	var id path.NodeID
	copy(id[:], name)
	return id
}

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// pnode is a path node on a memory network, accepting links from the
// nodes it was told about.
type pnode struct {
	*path.Node
	name  string
	peers *transport.PeerTable
	in    []transport.PeerLink
	table path.Table
}

func newNode(t *testing.T, n *memory.Network, name string) *pnode {
	t.Helper()
	node, err := path.NewNode(id(name), fast)
	if err != nil {
		t.Fatal(err)
	}
	p := &pnode{Node: node, name: name, peers: transport.NewPeerTable()}
	l, err := n.Listen(context.Background(), transport.ListenConfig{Address: name}, transport.Admission{Peers: p.peers})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = node.Serve(memory.Name, l)
	}()
	t.Cleanup(func() {
		_ = node.Close()
		_ = l.Close()
		<-served
	})
	return p
}

// dial makes from keep a link to to.
func dial(n *memory.Network, from, to *pnode) {
	secret := []byte(from.name + ">" + to.name)
	to.in = append(to.in, transport.PeerLink{Peer: transport.Identity{Node: id(from.name)}, Verifier: secret})
	to.peers.Set(to.in)
	from.table.Links = append(from.table.Links, path.Link{Node: id(to.name), Endpoints: []path.Endpoint{{
		Transport: memory.Name, Dialer: n, Address: to.name, Config: transport.DialConfig{Credential: secret},
	}}})
	from.Update(from.table)
}

// end is a node's WireGuard device straight on a channel TUN.
type end struct {
	key netmap.WireGuardPrivateKey
	tun *tuntest.ChannelTUN
	dev *wg.Device
}

func newEnd(t *testing.T, n *pnode) *end {
	e := &end{key: netmap.GenerateWireGuardKey(), tun: tuntest.NewChannelTUN()}
	e.dev = wg.New(n.name, e.tun.TUN(), n.NewBind(), nil)
	t.Cleanup(func() { _ = e.dev.Close() })
	return e
}

func configure(t *testing.T, d *wg.Device, key netmap.WireGuardPrivateKey, peers ...wg.Peer) {
	t.Helper()
	if err := d.Configure(key, peers); err != nil {
		t.Fatal(err)
	}
}

func setPeers(t *testing.T, n *pnode, set map[*path.Bind][]path.Peer) {
	t.Helper()
	if err := n.SetPeers(set); err != nil {
		t.Fatal(err)
	}
}

// expect waits for a packet on ch that p accepts.
func expect(t *testing.T, ch <-chan []byte, what string, ok func(packettest.Packet) bool) {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case b := <-ch:
			if p, parsed := packettest.Parse(b); parsed && ok(p) {
				return
			}
		case <-deadline:
			t.Fatalf("no %s", what)
		}
	}
}

// One node, one router, two WireGuard devices: the overlay device with a
// device peer, and an egress device whose exit claims the default routes.
// Both claim overlapping allowed IPs in their own device, which one
// device couldn't hold; the router picks the device.
func TestTwoDevicesBehindOneRouter(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, b, x := newNode(t, net, "A"), newNode(t, net, "B"), newNode(t, net, "X")
	dial(net, a, b)
	dial(net, a, x)

	aTUN := tuntest.NewChannelTUN()
	r := router.New(aTUN.TUN())
	t.Cleanup(func() { _ = r.Close() })
	overlayEgress, err := r.NewEgress("overlay", 1400)
	if err != nil {
		t.Fatal(err)
	}
	exitEgress, err := r.NewEgress("exit", 1400)
	if err != nil {
		t.Fatal(err)
	}
	aKey := netmap.GenerateWireGuardKey()
	overlay := wg.New("overlay", overlayEgress, a.NewBind(), nil)
	exit := wg.New("exit", exitEgress, a.NewBind(), nil)
	t.Cleanup(func() { _ = overlay.Close() })
	t.Cleanup(func() { _ = exit.Close() })
	// A peer key lives in one device: all of A's Binds are set at once.
	setPeers(t, a, map[*path.Bind][]path.Peer{
		overlay.Bind(): {{ID: id("B"), FirstHops: []path.NodeID{id("B")}}},
		exit.Bind():    {{ID: id("X"), FirstHops: []path.NodeID{id("X")}}},
	})
	bEnd, xEnd := newEnd(t, b), newEnd(t, x)
	setPeers(t, b, map[*path.Bind][]path.Peer{bEnd.dev.Bind(): {{ID: id("A"), FirstHops: []path.NodeID{id("A")}}}})
	setPeers(t, x, map[*path.Bind][]path.Peer{xEnd.dev.Bind(): {{ID: id("A"), FirstHops: []path.NodeID{id("A")}}}})

	aV4, aV6 := addr("100.64.0.1"), addr("fd00:1::1")
	aIPs := []netip.Prefix{prefix("100.64.0.1/32"), prefix("fd00:1::1/128")}
	configure(t, overlay, aKey, wg.Peer{Key: bEnd.key.Public(), Node: id("B"), AllowedIPs: []netip.Prefix{prefix("100.64.0.2/32"), prefix("fd00:1::2/128")}})
	configure(t, exit, aKey, wg.Peer{Key: xEnd.key.Public(), Node: id("X"), AllowedIPs: []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0")}})
	configure(t, bEnd.dev, bEnd.key, wg.Peer{Key: aKey.Public(), Node: id("A"), AllowedIPs: aIPs})
	configure(t, xEnd.dev, xEnd.key, wg.Peer{Key: aKey.Public(), Node: id("A"), AllowedIPs: aIPs})
	err = r.SetTable(router.Table{
		Overlay: []netip.Prefix{prefix("100.64.0.0/16"), prefix("fd00:1::/48")},
		Peers: []router.Route{
			{Prefix: prefix("100.64.0.2/32"), Egress: overlayEgress},
			{Prefix: prefix("fd00:1::2/128"), Egress: overlayEgress},
		},
		Rules: []router.Route{{Prefix: prefix("0.0.0.0/0"), Egress: exitEgress}, {Prefix: prefix("::/0"), Egress: exitEgress}},
		Local: []netip.Addr{aV4, aV6},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		src, dst netip.Addr
		at       *end
	}{
		{aV4, addr("100.64.0.2"), bEnd},
		{aV6, addr("fd00:1::2"), bEnd},
		{aV4, addr("192.0.2.80"), xEnd},
		{aV6, addr("2001:db8::80"), xEnd},
	} {
		// Retry: the first packets wait for WireGuard's handshake.
		stop := make(chan struct{})
		go func() {
			for seq := uint16(1); ; seq++ {
				select {
				case aTUN.Outbound <- packettest.Echo(c.src, c.dst, 1, seq, nil):
				case <-stop:
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
		expect(t, c.at.tun.Inbound, "ping to "+c.dst.String(), func(p packettest.Packet) bool { return p.Dst == c.dst && p.Src == c.src })
		close(stop)
		reply := packettest.UDPDatagram(netip.AddrPortFrom(c.dst, 53), netip.AddrPortFrom(c.src, 5353), []byte("back"))
		c.at.tun.Outbound <- reply
		expect(t, aTUN.Inbound, "reply from "+c.dst.String(), func(p packettest.Packet) bool {
			_, _, data, ok := packettest.UDPData(p)
			return ok && p.Src == c.dst && p.Dst == c.src && bytes.Equal(data, []byte("back"))
		})
	}

	// A peer that lets itself send A anything can't use A as a router: B,
	// from its own overlay address, to a LAN address behind A.
	configure(t, bEnd.dev, bEnd.key, wg.Peer{Key: aKey.Public(), Node: id("A"), AllowedIPs: []netip.Prefix{prefix("0.0.0.0/0")}})
	before := r.Counters().NotLocal
	bEnd.tun.Outbound <- packettest.UDPDatagram(netip.MustParseAddrPort("100.64.0.2:4000"), netip.MustParseAddrPort("192.168.1.5:53"), []byte("in"))
	deadline := time.Now().Add(wait)
	for r.Counters().NotLocal == before {
		if time.Now().After(deadline) {
			t.Fatalf("router %+v: the packet for 192.168.1.5 wasn't dropped as not local", r.Counters())
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case b := <-aTUN.Inbound:
		t.Fatalf("A's TUN got %x", b)
	default:
	}
}

// A peer without a path fails every send; that is counted, not logged as
// an error over and over.
func TestPathlessPeersDoNotFloodTheLog(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a := newNode(t, net, "A")
	var log recorder
	ch := tuntest.NewChannelTUN()
	key := netmap.GenerateWireGuardKey()
	dev := wg.New("overlay", ch.TUN(), a.NewBind(), slog.New(&log))
	t.Cleanup(func() { _ = dev.Close() })
	setPeers(t, a, map[*path.Bind][]path.Peer{dev.Bind(): {{ID: id("Z")}}})
	configure(t, dev, key, wg.Peer{Key: netmap.GenerateWireGuardKey().Public(), Node: id("Z"), AllowedIPs: []netip.Prefix{prefix("100.64.0.9/32")}})
	for range 3 {
		ch.Outbound <- packettest.Echo(addr("100.64.0.1"), addr("100.64.0.9"), 1, 1, nil)
	}
	deadline := time.Now().Add(wait)
	for a.Counters().NoPath == 0 {
		if time.Now().After(deadline) {
			t.Fatal("nothing tried the pathless peer")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if errs := log.errors(); len(errs) != 0 {
		t.Fatalf("logged as errors: %q", errs)
	}
}

// The name the log's handshake tracking computes for a peer is the one
// WireGuard's own messages carry, so a removed peer is forgotten.
func TestPeerNamesAreWireGuards(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a := newNode(t, net, "A")
	var log recorder
	ch := tuntest.NewChannelTUN()
	dev := wg.New("overlay", ch.TUN(), a.NewBind(), slog.New(&log))
	t.Cleanup(func() { _ = dev.Close() })
	peer := netmap.GenerateWireGuardKey().Public()
	configure(t, dev, netmap.GenerateWireGuardKey(), wg.Peer{Key: peer, Node: id("Z"), AllowedIPs: []netip.Prefix{prefix("100.64.0.9/32")}})
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, rec := range log.recs {
		if strings.HasPrefix(rec.Message, wg.PeerName(peer)+" - ") {
			return
		}
	}
	var msgs []string
	for _, rec := range log.recs {
		msgs = append(msgs, rec.Message)
	}
	t.Errorf("no message names %s: %q", wg.PeerName(peer), msgs)
}

type recorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec)
	return nil
}
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

func (r *recorder) errors() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.recs {
		if rec.Level >= slog.LevelError {
			out = append(out, rec.Message)
		}
	}
	return out
}

func TestConfigureKeepsSessionsAndRefusesBadPeers(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, b := newNode(t, net, "A"), newNode(t, net, "B")
	dial(net, a, b)
	aEnd, bEnd := newEnd(t, a), newEnd(t, b)
	setPeers(t, a, map[*path.Bind][]path.Peer{aEnd.dev.Bind(): {{ID: id("B"), FirstHops: []path.NodeID{id("B")}}}})
	setPeers(t, b, map[*path.Bind][]path.Peer{bEnd.dev.Bind(): {{ID: id("A"), FirstHops: []path.NodeID{id("A")}}}})
	toB := wg.Peer{Key: bEnd.key.Public(), Node: id("B"), AllowedIPs: []netip.Prefix{prefix("100.64.0.2/32")}}
	configure(t, aEnd.dev, aEnd.key, toB)
	configure(t, bEnd.dev, bEnd.key, wg.Peer{Key: aEnd.key.Public(), Node: id("A"), AllowedIPs: []netip.Prefix{prefix("100.64.0.1/32")}})

	ping := func() {
		t.Helper()
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			for {
				select {
				case aEnd.tun.Outbound <- packettest.Echo(addr("100.64.0.1"), addr("100.64.0.2"), 1, 1, nil):
				case <-stop:
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
		expect(t, bEnd.tun.Inbound, "ping", func(packettest.Packet) bool { return true })
	}
	ping()
	handshake := func() time.Time {
		t.Helper()
		peers, err := aEnd.dev.Peers()
		if err != nil || len(peers) != 1 || peers[0].Node != id("B") || peers[0].Key != toB.Key {
			t.Fatalf("peers %+v, %v", peers, err)
		}
		return peers[0].LastHandshake
	}
	first := handshake()
	if first.IsZero() {
		t.Fatal("no handshake after a ping")
	}

	// Same config, then more allowed IPs: the session stays.
	configure(t, aEnd.dev, aEnd.key, toB)
	toB.AllowedIPs = append(toB.AllowedIPs, prefix("fd00:1::2/128"))
	configure(t, aEnd.dev, aEnd.key, toB)
	ping()
	if got := handshake(); !got.Equal(first) {
		t.Fatalf("handshake at %v, was %v: reconfiguring restarted the session", got, first)
	}
	if peers, _ := aEnd.dev.Peers(); peers[0].TxBytes == 0 || peers[0].RxBytes == 0 {
		t.Fatalf("no traffic counted: %+v", peers[0])
	}

	other := netmap.GenerateWireGuardKey().Public()
	for name, peers := range map[string][]wg.Peer{
		"own key":         {{Key: aEnd.key.Public(), Node: id("C"), AllowedIPs: []netip.Prefix{prefix("100.64.0.3/32")}}},
		"zero key":        {{Node: id("C")}},
		"zero node":       {{Key: other}},
		"key twice":       {toB, {Key: toB.Key, Node: id("C")}},
		"node twice":      {toB, {Key: other, Node: id("B")}},
		"overlapping IPs": {toB, {Key: other, Node: id("C"), AllowedIPs: []netip.Prefix{prefix("100.64.0.0/24")}}},
		"invalid IP":      {{Key: other, Node: id("C"), AllowedIPs: []netip.Prefix{{}}}},
	} {
		if err := aEnd.dev.Configure(aEnd.key, peers); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := aEnd.dev.Configure(netmap.WireGuardPrivateKey{}, nil); err == nil {
		t.Error("zero private key accepted")
	}
	if handshake().IsZero() {
		t.Fatal("a refused config changed the device")
	}

	configure(t, aEnd.dev, aEnd.key)
	if peers, err := aEnd.dev.Peers(); err != nil || len(peers) != 0 {
		t.Fatalf("peers after removing all: %+v, %v", peers, err)
	}
}

// WireGuard never gets a socket: no listen port, no firewall mark.
func TestNoListenPortOrMark(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a := newNode(t, net, "A")
	e := newEnd(t, a)
	configure(t, e.dev, e.key)
	peers, err := e.dev.Peers()
	if err != nil || len(peers) != 0 {
		t.Fatalf("%+v %v", peers, err)
	}
	if s := wg.IpcGetForTest(e.dev); strings.Contains(s, "listen_port=") || strings.Contains(s, "fwmark=") {
		t.Fatalf("device reports a port or a mark:\n%s", s)
	}
}
