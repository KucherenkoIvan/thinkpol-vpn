package path_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
)

// relayed sets up A → R → B: both ends dial the relay, which routes each to
// the other and is the only first hop either has.
func relayed(t *testing.T, f *fabric) (a, b *rawBind) {
	f.add("A", "R", "B")
	f.dial("A", "R")
	f.dial("B", "R")
	f.route("R", "A", "A")
	f.route("R", "B", "B")
	return f.bind("A", peer("B", "R")), f.bind("B", peer("A", "R"))
}

func TestRelayDelivers(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := relayed(t, f)
		toB := a.endpoint(t, "B")
		a.send(t, toB, "hello B")
		got := b.expect(t, "hello B")
		if got.ep.DstToString() != hexID("A") {
			t.Fatalf("B sees the packet from %q, want A's id", got.ep.DstToString())
		}
		// WireGuard answers to the endpoint a packet came with.
		b.send(t, got.ep, "hello A")
		back := a.expect(t, "hello A")
		if back.ep.DstToString() != toB.DstToString() || string(back.ep.DstToBytes()) != string(toB.DstToBytes()) {
			t.Fatal("WireGuard would see B at a different address on the way back")
		}
		if hop, _ := a.Current(id("B")); hop != id("R") {
			t.Fatalf("A sends to B through %s, want R", hop)
		}
		r := f.node("R").Counters()
		if r.Forwarded != 2 || r.Delivered != 0 || r.NoRoute != 0 {
			t.Fatalf("relay counters %+v, want 2 forwarded and nothing else", r)
		}
	})
}

func TestRelayRefusesDestinationsNotInItsTable(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		f.add("A", "R", "B")
		f.dial("A", "R")
		f.dial("B", "R")
		f.route("R", "A", "A") // no route to B, though B is adjacent
		a, b := f.bind("A", peer("B", "R")), f.bind("B", peer("A", "R"))

		a.send(t, a.endpoint(t, "B"), "for B")
		eventually(t, "the relay drops the packet", func() bool { return f.node("R").Counters().NoRoute == 1 })
		b.expectNothing(t, 100*time.Millisecond)

		b.send(t, b.endpoint(t, "A"), "for A") // the listed destination
		a.expect(t, "for A")
		if c := f.node("R").Counters(); c.Forwarded != 1 || c.NoRoute != 1 {
			t.Fatalf("relay counters %+v, want 1 forwarded and 1 refused", c)
		}
	})
}

func TestEndpointsDropWhatIsNotForThem(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		// A believes B is adjacent and a relay; B has no routes.
		f.add("A", "B", "C")
		f.dial("A", "B")
		a := f.bind("A", peer("C", "B"), peer("B", "B"))
		b := f.bind("B") // no peers: A is a stranger to B's WireGuard device

		a.send(t, a.endpoint(t, "C"), "for C")
		a.send(t, a.endpoint(t, "B"), "for B")
		eventually(t, "B drops both", func() bool {
			c := f.node("B").Counters()
			return c.NoRoute == 1 && c.UnknownPeer == 1
		})
		b.expectNothing(t, 50*time.Millisecond)
	})
}

func TestHopLimitEndsRoutingLoops(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		// Three relays whose routes to B go round in a circle.
		f.add("A", "R1", "R2", "R3")
		f.dial("A", "R1")
		f.dial("R1", "R2")
		f.dial("R2", "R3")
		f.dial("R3", "R1")
		f.waitUp("R1", "R3")
		f.route("R1", "B", "R2")
		f.route("R2", "B", "R3")
		f.route("R3", "B", "R1")
		a := f.bind("A", peer("B", "R1"))

		a.send(t, a.endpoint(t, "B"), "lost in a loop")
		total := func() path.Counters {
			var sum path.Counters
			for _, r := range []string{"R1", "R2", "R3"} {
				c := f.node(r).Counters()
				sum.Forwarded += c.Forwarded
				sum.HopLimit += c.HopLimit
			}
			return sum
		}
		eventually(t, "the packet dies", func() bool { return total().HopLimit == 1 })
		time.Sleep(50 * time.Millisecond)
		if c := total(); c.Forwarded != path.DefaultHopLimit-1 || c.HopLimit != 1 {
			t.Fatalf("relays forwarded %d times and dropped %d, want %d and 1", c.Forwarded, c.HopLimit, path.DefaultHopLimit-1)
		}
	})
}

// twoRelays sets up A and B with two relays, R1 first in both ends'
// priority order.
func twoRelays(t *testing.T, f *fabric) (a, b *rawBind) {
	f.add("A", "B", "R1", "R2")
	for _, end := range []string{"A", "B"} {
		for _, r := range []string{"R1", "R2"} {
			f.dial(end, r)
			f.route(r, end, end)
		}
	}
	return f.bind("A", peer("B", "R1", "R2")), f.bind("B", peer("A", "R1", "R2"))
}

func TestSwitchesPathWhenTheFirstHopGoesSilent(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f)
		toB := a.endpoint(t, "B")
		a.send(t, toB, "before")
		b.expect(t, "before")
		if hop, _ := a.Current(id("B")); hop != id("R1") {
			t.Fatalf("A starts on %s, want R1", hop)
		}

		// R1 dies without a word: nothing reports it, its links just go quiet.
		f.silence("A", "R1")
		f.silence("B", "R1")
		start := time.Now()
		got := keepSending(t, a, b, toB, "after")
		took := time.Since(start)
		if hop, _ := a.Current(id("B")); hop != id("R2") {
			t.Fatalf("A now sends through %s, want R2", hop)
		}
		b.send(t, got.ep, "and back")
		a.expect(t, "and back")
		if hop, _ := b.Current(id("A")); hop != id("R2") {
			t.Fatalf("B now sends through %s, want R2", hop)
		}
		if limit := 5 * fastOptions.DeadAfter; took > limit {
			t.Fatalf("switching took %v, more than %v", took, limit)
		}
		t.Logf("switched to R2 %v after R1 went silent (DeadAfter %v)", took, fastOptions.DeadAfter)
	})
}

func TestSwitchesPathWhenTheRelayCloses(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f)
		toB := a.endpoint(t, "B")
		a.send(t, toB, "before")
		b.expect(t, "before")
		_ = f.node("R1").Close()
		keepSending(t, a, b, toB, "after")
		if hop, _ := a.Current(id("B")); hop != id("R2") {
			t.Fatalf("A now sends through %s, want R2", hop)
		}
	})
}

// When only A loses R1, B can still reach R1 but R1 can't reach A: B must
// answer the way A's packets came, not by its own priority order.
func TestFollowsThePathThePeerUses(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f)
		toB, toA := a.endpoint(t, "B"), b.endpoint(t, "A")
		a.send(t, toB, "before")
		b.expect(t, "before")

		f.silence("A", "R1")
		got := keepSending(t, a, b, toB, "through R2")

		// By its own order B would pick R1, which can't deliver to A.
		b.send(t, toA, "own choice")
		a.expectNothing(t, 100*time.Millisecond)
		if hop, _ := b.Current(id("A")); hop != id("R1") {
			t.Fatalf("B's own choice is %s, want R1", hop)
		}
		// The endpoint WireGuard adopts from A's latest packet leads back
		// via R2.
		if got.ep.DstToString() != hexID("A") {
			t.Fatalf("A's packet came from %s", got.ep.DstToString())
		}
		a.send(t, toB, "latest")
		latest := b.expect(t, "latest")
		b.send(t, latest.ep, "followed")
		a.expect(t, "followed")
		if hop, _ := b.Current(id("A")); hop != id("R2") {
			t.Fatalf("B follows A through %s, want R2", hop)
		}
	})
}

func TestBindContract(t *testing.T) {
	f := newFabric(t, 0)
	f.add("A", "R")
	f.dial("A", "R")
	b := f.node("A").NewBind()
	if err := b.SetPeers([]path.Peer{peer("B", "R")}); err != nil {
		t.Fatal(err)
	}
	if err := f.node("A").NewBind().SetPeers([]path.Peer{peer("B", "R")}); !errors.Is(err, path.ErrPeerTaken) {
		t.Fatalf("a second bind took the same peer: %v", err)
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
	other, _ := b.ParseEndpoint(hexID("C"))
	if toB.DstIP() == other.DstIP() {
		t.Fatal("two peers share an address in WireGuard's rate limiter")
	}
	if err := b.Send([][]byte{[]byte("x")}, other); !errors.Is(err, path.ErrUnknownPeer) {
		t.Fatalf("sent to a peer the bind doesn't have: %v", err)
	}
	if err := b.Send([][]byte{make([]byte, path.MaxMessageSize+1)}, toB); !errors.Is(err, path.ErrMessageSize) {
		t.Fatalf("sent an oversized message: %v", err)
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
