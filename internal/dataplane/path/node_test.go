package path_test

import (
	"testing"
	"time"

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
		if hop := a.current("B"); hop != "R" {
			t.Fatalf("A sends to B through %q, want R", hop)
		}
		r := f.node("R").Counters()
		if r.Forwarded != 2 || r.Delivered != 0 || r.NoRoute != 0 || r.Spoofed != 0 {
			t.Fatalf("relay counters %+v, want 2 forwarded and nothing else", r)
		}
		if c := f.node("B").Counters(); c.Delivered != 1 || c.Sent != 1 {
			t.Fatalf("B's counters %+v, want 1 delivered and 1 sent", c)
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
		// Three relays whose routes to B go round in a circle; their routes
		// back to the sources pass the reverse-path check.
		f.add("A", "R1", "R2", "R3")
		f.dial("A", "R1")
		f.dial("R1", "R2")
		f.dial("R2", "R3")
		f.dial("R3", "R1")
		f.waitUp("R1", "R3")
		f.route("R1", "B", "R2")
		f.route("R2", "B", "R3")
		f.route("R3", "B", "R1")
		for _, src := range []string{"A", "X"} {
			f.route("R1", src, src, "R3")
			f.route("R2", src, "R1")
			f.route("R3", src, "R2")
		}
		total := func() path.Counters {
			var sum path.Counters
			for _, r := range []string{"R1", "R2", "R3"} {
				c := f.node(r).Counters()
				sum.Forwarded += c.Forwarded
				sum.HopLimit += c.HopLimit
				sum.Spoofed += c.Spoofed
			}
			return sum
		}
		check := func(round uint64) {
			t.Helper()
			eventually(t, "the packet dies", func() bool { return total().HopLimit == round })
			time.Sleep(50 * time.Millisecond)
			want := round * (path.DefaultHopLimit - 1)
			if c := total(); c.Forwarded != want || c.HopLimit != round || c.Spoofed != 0 {
				t.Fatalf("relays forwarded %d times and dropped %d (%d spoofed), want %d and %d", c.Forwarded, c.HopLimit, c.Spoofed, want, round)
			}
		}

		a := f.bind("A", peer("B", "R1"))
		a.send(t, a.endpoint(t, "B"), "lost in a loop")
		check(1)

		// A neighbor can't buy a longer loop: relays cap what arrives at
		// their own hop limit.
		x := f.rawLink("X", "R1")
		if err := x.WritePacket(packet(255, "B", "X", wgMsg("255 hops"))); err != nil {
			t.Fatal(err)
		}
		check(2)
	})
}

// The reverse-path check is loose: a relay drops a packet whose source it
// doesn't know (no route to it, not adjacent); a destination delivers what
// any adjacent node brings, since routes needn't be symmetric.
func TestRelaysDropSourcesTheyDontKnow(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := relayed(t, f)
		toR := f.rawLink("X", "R")
		if err := toR.WritePacket(packet(8, "B", "Q", wgMsg("from nowhere"))); err != nil {
			t.Fatal(err)
		}
		eventually(t, "the relay drops it", func() bool { return f.node("R").Counters().Spoofed == 1 })
		if err := toR.WritePacket(packet(8, "B", "A", wgMsg("A, says X"))); err != nil {
			t.Fatal(err)
		}
		b.await(t, "A, says X") // WireGuard drops what isn't really A's
		a.send(t, a.endpoint(t, "B"), "the real A")
		b.await(t, "the real A")
	})
}

// The asymmetric case in devmap's reference map (internal/devmap/
// reference.yaml): device-a reaches server-3 through server-1 and server-2,
// but server-2 routes back to device-a directly, so server-3's replies
// arrive through a hop that isn't one of device-a's first hops for it.
// Both directions deliver, and device-a keeps its own first hop.
func TestAsymmetricRoutesDeliverBothWays(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		f.add("a", "b", "s1", "s2", "s3")
		f.dial("a", "s1")
		f.dial("a", "s2")
		f.dial("b", "s1")
		f.dial("b", "s2")
		f.dial("s1", "s2")
		f.dial("s2", "s3")
		f.route("s1", "b", "b")
		f.route("s1", "a", "a")
		f.route("s1", "s2", "s2")
		f.route("s1", "s3", "s2")
		f.route("s2", "b", "b")
		f.route("s2", "a", "a", "s1")
		f.route("s2", "s3", "s3")
		a := f.bind("a", peer("s1", "s1"), peer("b", "s1", "s2"), peer("s2", "s1"), peer("s3", "s1"))
		b := f.bind("b", peer("a", "s1", "s2"))
		s2 := f.bind("s2", peer("a", "s1"))
		s3 := f.bind("s3", peer("a", "s2"))

		for _, far := range []struct {
			name string
			bind *rawBind
		}{{"s3", s3}, {"s2", s2}, {"b", b}} {
			a.send(t, a.endpoint(t, far.name), "to "+far.name)
			got := far.bind.await(t, "to "+far.name)
			far.bind.send(t, got.ep, "from "+far.name)
			back := a.await(t, "from "+far.name)
			a.send(t, back.ep, "again "+far.name)
			far.bind.await(t, "again "+far.name)
		}
		if hop := a.current("s3"); hop != "s1" {
			t.Fatalf("a sends to s3 through %q, want its first hop s1", hop)
		}
		for _, n := range []string{"s1", "s2"} {
			if c := f.node(n).Counters(); c.Spoofed != 0 || c.NoRoute != 0 {
				t.Fatalf("%s dropped traffic: %+v", n, c)
			}
		}
	})
}

func TestFramesOnTheLink(t *testing.T) {
	f := newFabric(t, 0)
	f.add("R", "B")
	f.dial("B", "R")
	f.route("R", "B", "B")
	l := f.rawLink("X", "R")
	for _, frame := range [][]byte{
		{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0},      // unknown kind
		packet(0, "B", "X", wgMsg("no hops")),  // no hops left
		packet(5, "B", "X", nil),               // no message
		packet(1, "B", "X", wgMsg("last hop")), // would reach B with none left
		{3, 0, 1, 2, 3, 4, 5, 6, 7, 8},         // a reply to no probe of R's
	} {
		if err := l.WritePacket(frame); err != nil {
			t.Fatal(err)
		}
	}
	r := f.node("R")
	eventually(t, "R drops all four", func() bool {
		c := r.Counters()
		return c.Malformed == 3 && c.HopLimit == 1
	})
	if err := l.WritePacket(packet(2, "B", "X", wgMsg("for B"))); err != nil {
		t.Fatal(err)
	}
	eventually(t, "R forwards to B", func() bool { return r.Counters().Forwarded == 1 })
	eventually(t, "B gets it from X, a stranger", func() bool { return f.node("B").Counters().UnknownPeer == 1 })
}
