package path_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

func TestBindContract(t *testing.T) {
	f := newFabric(t, 0)
	f.add("A", "R")
	f.dial("A", "R")
	n := f.node("A")
	b := n.NewBind()
	if err := b.SetPeers([]path.Peer{peer("B", "R")}); err != nil {
		t.Fatal(err)
	}
	other := n.NewBind()
	if err := other.SetPeers([]path.Peer{peer("B", "R")}); !errors.Is(err, path.ErrPeerTaken) {
		t.Fatalf("a second bind took the same peer: %v", err)
	}
	// Moving a peer between binds is one step.
	if err := n.SetPeers(map[*path.Bind][]path.Peer{b: nil, other: {peer("B", "R")}}); err != nil {
		t.Fatalf("moving B: %v", err)
	}
	if err := b.SetPeers([]path.Peer{peer("B", "R")}); !errors.Is(err, path.ErrPeerTaken) {
		t.Fatalf("B is in two binds: %v", err)
	}
	other.Release()
	if err := other.SetPeers(nil); !errors.Is(err, path.ErrReleased) {
		t.Fatalf("a released bind took peers: %v", err)
	}
	if err := b.SetPeers([]path.Peer{peer("B", "R")}); err != nil {
		t.Fatalf("B wasn't freed by Release: %v", err)
	}

	for _, s := range []string{"", "127.0.0.1:51820", "[::1]:51820", "0000000000000000", hexID("B") + "00", "zz"} {
		if _, err := b.ParseEndpoint(s); err == nil {
			t.Fatalf("ParseEndpoint(%q) accepted a non-node-id", s)
		}
	}
	toB, err := b.ParseEndpoint(hexID("B"))
	if err != nil {
		t.Fatal(err)
	}
	if !toB.DstIP().IsValid() || toB.DstToString() != hexID("B") {
		t.Fatalf("endpoint %s / %s", toB.DstToString(), toB.DstIP())
	}
	toC, _ := b.ParseEndpoint(hexID("C"))
	if toB.DstIP() == toC.DstIP() {
		t.Fatal("two peers share an address in WireGuard's rate limiter")
	}
	if err := b.Send([][]byte{wgMsg("x")}, toC); !errors.Is(err, path.ErrUnknownPeer) {
		t.Fatalf("sent to a peer the bind doesn't have: %v", err)
	}
	if err := b.Send([][]byte{make([]byte, path.MaxMessageSize+1)}, toB); !errors.Is(err, path.ErrMessageSize) {
		t.Fatalf("sent an oversized message: %v", err)
	}
	if err := b.SetMark(0); err != nil {
		t.Fatal(err)
	}
	if err := b.SetMark(51820); !errors.Is(err, path.ErrNoSocket) {
		t.Fatalf("SetMark with a mark: %v", err)
	}

	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(0); err == nil {
		t.Fatal("opened twice")
	}
	result := make(chan error, 1)
	go func() {
		_, err := fns[0](make([][]byte, 1), make([]int, 1), make([]conn.Endpoint, 1))
		result <- err
	}()
	_ = b.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after Close: %v", err)
		}
	case <-time.After(wait):
		t.Fatal("Close didn't unblock receive")
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = b.Close()
}

// A message too long for the buffer WireGuard gives is dropped and counted.
func TestBindDropsWhatWireGuardCantHold(t *testing.T) {
	f := newFabric(t, 0)
	a, b := relayed(t, f)
	_ = b.Close() // ends the fixture's receive loop; read by hand instead
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	a.send(t, a.endpoint(t, "B"), "too long")
	go func() { _, _ = fns[0]([][]byte{make([]byte, 8)}, make([]int, 1), make([]conn.Endpoint, 1)) }()
	eventually(t, "B drops it", func() bool { return f.node("B").Counters().Malformed == 1 })
	if c := f.node("B").Counters(); c.Delivered != 0 {
		t.Fatalf("delivered %d", c.Delivered)
	}
}

func TestOptionsAreChecked(t *testing.T) {
	for name, o := range map[string]path.Options{
		"DeadAfter not above ProbeInterval": {ProbeInterval: time.Second, DeadAfter: time.Second},
		"RedialMax below RedialMin":         {RedialMin: time.Second, RedialMax: time.Millisecond},
	} {
		if _, err := path.NewNode(id("A"), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := path.NewNode(path.NodeID{}, path.Options{}); err == nil {
		t.Error("zero node id accepted")
	}
}

func TestServeRefusesLinksOfAnotherSpace(t *testing.T) {
	f := newFabric(t, 0)
	ours := transport.SpaceID{1}
	f.opts.Space = ours
	f.add("R")
	secret := f.accept("R", "X", transport.SpaceID{2})
	// Redial until the listener has taken up its new table.
	eventually(t, "R refuses X", func() bool {
		l, err := f.tr.Dial(context.Background(), "R", transport.DialConfig{Credential: secret})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		time.Sleep(5 * time.Millisecond)
		return f.node("R").Counters().OtherSpace > 0
	})
	if _, ok := f.neighbor("R", "X"); ok {
		t.Fatal("R keeps a link to a node of another space")
	}
}

func TestStatusDescribesLinks(t *testing.T) {
	f := newFabric(t, 0)
	a, b := relayed(t, f)
	a.send(t, a.endpoint(t, "B"), "counted")
	b.expect(t, "counted")
	at, ok := f.neighbor("A", "R")
	if !ok || !at.Up || !at.Dialed || len(at.Links) != 1 {
		t.Fatalf("A's view of R: %+v", at)
	}
	l := at.Links[0]
	if !l.Dialed || l.Transport != memory.Name || l.Endpoint != 0 || !l.Active || !l.Up || l.PacketsOut == 0 || l.BytesOut < 18+48 || l.PacketsIn == 0 {
		t.Fatalf("A's link to R: %+v", l)
	}
	back, _ := f.neighbor("R", "A")
	if len(back.Links) != 1 || back.Links[0].Dialed || back.Links[0].Endpoint != -1 || back.Links[0].Transport != memory.Name || back.Dialed {
		t.Fatalf("R's view of A: %+v", back)
	}
	if hop, since, ok := a.Current(id("B")); !ok || hop != id("R") || since.IsZero() {
		t.Fatalf("Current: %s %v %v", hop, since, ok)
	}
}

// Two up links to one neighbor: traffic stays on one of them.
func TestTrafficSticksToOneLinkPerNeighbour(t *testing.T) {
	f := newFabric(t, 0)
	a, b := relayed(t, f)
	f.dial("R", "A") // a second link between A and R
	eventually(t, "A has two links to R", func() bool {
		s, _ := f.neighbor("A", "R")
		return len(s.Links) == 2 && s.Links[0].Up && s.Links[1].Up
	})
	toB := a.endpoint(t, "B")
	for range 100 {
		a.send(t, toB, "steady")
		b.expect(t, "steady")
	}
	s, _ := f.neighbor("A", "R")
	lo, hi := s.Links[0].PacketsOut, s.Links[1].PacketsOut
	if lo > hi {
		lo, hi = hi, lo
	}
	if hi < 100 || lo > 20 {
		t.Fatalf("packets out per link: %d and %d, want all data on one", lo, hi)
	}
}

// A probe reply counts, for liveness and the round trip, only if it answers
// a probe the link is waiting for, and only once.
func TestProbeRepliesMustMatch(t *testing.T) {
	f := newFakeFabric(t, 0)
	f.add("A")
	table := transport.NewPeerTable(transport.PeerLink{Peer: transport.Identity{Node: id("A")}, Verifier: []byte("secret A>Z")})
	l, err := f.tr.Listen(context.Background(), transport.ListenConfig{Address: "Z", Peers: table})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	a := f.node("A")
	a.Update(path.Table{Links: []path.Link{{Node: id("Z"), Endpoints: []path.Endpoint{{
		Transport: memory.Name, Dialer: f.tr, Address: "Z", Config: transport.DialConfig{Credential: []byte("secret A>Z")},
	}}}}})
	z, _, err := l.Accept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, transport.MaxPacketSize)
	n, err := z.ReadPacket(buf)
	if err != nil || n != 10 || buf[0] != 2 {
		t.Fatalf("A's first frame %x (%v), want a probe", buf[:n], err)
	}
	probe := append([]byte(nil), buf[:n]...)
	reply := func(token []byte) {
		t.Helper()
		if err := z.WritePacket(append([]byte{3, 0}, token...)); err != nil {
			t.Fatal(err)
		}
	}
	rtt := func() (bool, time.Duration) {
		s, _ := f.neighbor("A", "Z")
		return s.Up, s.RTT
	}

	wrong := append([]byte(nil), probe[2:]...)
	wrong[0] ^= 0xff
	reply(wrong)
	time.Sleep(20 * time.Millisecond)
	if up, d := rtt(); up || d != 0 {
		t.Fatalf("a reply to no probe counted: up %v, RTT %v", up, d)
	}
	f.clock.add(40 * time.Millisecond)
	reply(probe[2:])
	eventually(t, "the reply proves the link", func() bool { up, _ := rtt(); return up })
	if _, d := rtt(); d != 40*time.Millisecond {
		t.Fatalf("RTT %v, want 40ms", d)
	}
	f.clock.add(40 * time.Millisecond)
	reply(probe[2:]) // a replay of the reply
	time.Sleep(20 * time.Millisecond)
	if _, d := rtt(); d != 40*time.Millisecond {
		t.Fatalf("a repeated reply moved the RTT to %v", d)
	}
}

// Adjacent nodes nothing refers to any more are forgotten.
func TestNeighboursNoLongerUsedAreForgotten(t *testing.T) {
	f := newFabric(t, 0)
	f.add("A", "R")
	f.dial("A", "R")
	f.node("A").Update(path.Table{})
	eventually(t, "A forgets R", func() bool {
		_, ok := f.neighbor("A", "R")
		return !ok
	})
}

func TestMessageBudget(t *testing.T) {
	// A 1500-byte IPv6 path: 1452 bytes for the transport's units.
	unshaped := transport.Shaping{}
	if got, want := path.MessageBudget(udp.New(udp.Options{}), unshaped, 1452), 1452-74-path.HeaderSize; got != want {
		t.Fatalf("udp budget %d, want %d", got, want)
	}
	if got := path.MessageBudget(memory.NewNetwork(memory.Datagram), unshaped, 100_000); got != path.MaxMessageSize {
		t.Fatalf("budget %d, want the cap", got)
	}
	if got := path.MessageBudget(udp.New(udp.Options{}), unshaped, 80); got != 0 {
		t.Fatalf("budget %d, want 0", got)
	}
	// Bucket padding: the largest bucket that fits the unit sets the budget.
	shaped := transport.Shaping{Padding: transporttest.Buckets(256, 1024, 1500)}
	if got := path.MessageBudget(memory.NewNetwork(memory.Datagram, memory.AcceptShaping()), shaped, 1452); got != 1024-path.HeaderSize {
		t.Fatalf("shaped budget %d, want %d", got, 1024-path.HeaderSize)
	}
}
