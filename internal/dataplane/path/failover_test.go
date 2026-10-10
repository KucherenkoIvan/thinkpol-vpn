package path_test

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// twoRelays sets up A and B (A has the lower id, so A leads and B follows)
// with two relays; each end's priority order is given.
func twoRelays(t *testing.T, f *fabric, aHops, bHops []string) (a, b *rawBind) {
	f.add("A", "B", "R1", "R2")
	for _, end := range []string{"A", "B"} {
		for _, r := range []string{"R1", "R2"} {
			f.dial(end, r)
			f.route(r, end, end)
		}
	}
	return f.bind("A", peer("B", aHops...)), f.bind("B", peer("A", bHops...))
}

var r1r2 = []string{"R1", "R2"}

// The NFR on the wall clock: a first hop that dies silently is replaced
// within a few DeadAfters.
func TestSwitchesPathWhenTheFirstHopGoesSilent(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB := a.endpoint(t, "B")
		a.send(t, toB, "before")
		b.expect(t, "before")
		if hop := a.current("B"); hop != "R1" {
			t.Fatalf("A starts on %q, want R1", hop)
		}

		// R1 dies without a word: nothing reports it, its links just go quiet.
		f.silence("A", "R1", true)
		f.silence("B", "R1", true)
		start := time.Now()
		got := keepSending(t, a, b, toB, "after")
		took := time.Since(start)
		if hop := a.current("B"); hop != "R2" {
			t.Fatalf("A now sends through %q, want R2", hop)
		}
		b.send(t, got.ep, "and back")
		a.expect(t, "and back")
		if hop := b.current("A"); hop != "R2" {
			t.Fatalf("B now sends through %q, want R2", hop)
		}
		if limit := 10 * f.opts.DeadAfter; took > limit {
			t.Fatalf("switching took %v, more than %v", took, limit)
		}
		t.Logf("switched to R2 %v after R1 went silent (DeadAfter %v)", took, f.opts.DeadAfter)
	})
}

// On the fake clock: the switch comes once the link has been silent for
// DeadAfter, not before.
func TestSwitchTimingOnTheFakeClock(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB := a.endpoint(t, "B")
		a.send(t, toB, "before")
		b.expect(t, "before")
		f.advance(5*f.opts.ProbeInterval, func() { _ = a.Send([][]byte{wgMsg("steady")}, toB) })
		if hop := a.current("B"); hop != "R1" {
			t.Fatalf("A is on %q before anything failed, want R1", hop)
		}

		f.silence("A", "R1", true)
		f.silence("B", "R1", true)
		var elapsed, switchedAt time.Duration
		f.advance(2*f.opts.DeadAfter, func() {
			elapsed += fakeStep
			_ = a.Send([][]byte{wgMsg("probe")}, toB)
			if switchedAt == 0 && a.current("B") == "R2" {
				switchedAt = elapsed
			}
		})
		o := f.opts
		if switchedAt < o.DeadAfter-o.ProbeInterval-2*fakeStep || switchedAt > o.DeadAfter+2*fakeStep {
			t.Fatalf("switched %v after R1 went silent, want between %v and %v", switchedAt,
				o.DeadAfter-o.ProbeInterval-2*fakeStep, o.DeadAfter+2*fakeStep)
		}
	})
}

func TestSwitchesPathWhenTheRelayCloses(t *testing.T) {
	eachSemantics(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB := a.endpoint(t, "B")
		a.send(t, toB, "before")
		b.expect(t, "before")
		_ = f.node("R1").Close()
		keepSending(t, a, b, toB, "after")
		if hop := a.current("B"); hop != "R2" {
			t.Fatalf("A now sends through %q, want R2", hop)
		}
	})
}

// pingPong has A send and B answer to the endpoint A's packet came with,
// as WireGuard does, and returns the hops each used.
func pingPong(t *testing.T, a, b *rawBind, toB conn.Endpoint, tag string) (aHop, bHop string) {
	t.Helper()
	a.send(t, toB, tag)
	got := b.await(t, tag)
	b.send(t, got.ep, tag+" back")
	a.await(t, tag+" back")
	return a.current("B"), b.current("A")
}

// Ends that start on different hops converge on the leader's and stay.
func TestTheFollowerConvergesOnTheLeadersPath(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, []string{"R2", "R1"})
		// B speaks first, by its own order.
		b.send(t, b.endpoint(t, "A"), "hello from B")
		got := a.expect(t, "hello from B")
		if hop := b.current("A"); hop != "R2" {
			t.Fatalf("B starts on %q, want R2", hop)
		}
		// A leads: it answers by its own order, not the way B came.
		a.send(t, got.ep, "hello from A")
		got = b.expect(t, "hello from A")
		if hop := a.current("B"); hop != "R1" {
			t.Fatalf("A answers through %q, want R1", hop)
		}
		b.send(t, got.ep, "following")
		a.expect(t, "following")
		_, aSince, _ := a.Current(id("B"))
		_, bSince, _ := b.Current(id("A"))
		for i := range 20 {
			f.clock.add(fakeStep)
			aHop, bHop := pingPong(t, a, b, a.endpoint(t, "B"), "round")
			if aHop != "R1" || bHop != "R1" {
				t.Fatalf("round %d: A on %q, B on %q, want both on R1", i, aHop, bHop)
			}
		}
		_, aNow, _ := a.Current(id("B"))
		_, bNow, _ := b.Current(id("A"))
		if !aNow.Equal(aSince) || !bNow.Equal(bSince) {
			t.Fatal("an end switched hops back and forth")
		}
	})
}

// When only A, the leader, loses R1, B can still reach R1 but R1 can't
// reach A: B must answer the way A's packets came, not by its own order.
func TestTheFollowerTakesTheLeadersPath(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB, toA := a.endpoint(t, "B"), b.endpoint(t, "A")
		pingPong(t, a, b, toB, "before")

		f.silence("A", "R1", true)
		f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, nil)
		a.send(t, toB, "through R2")
		b.expect(t, "through R2")
		if hop := a.current("B"); hop != "R2" {
			t.Fatalf("A sends through %q, want R2", hop)
		}

		// By its own order B would pick R1, which can't deliver to A.
		b.send(t, toA, "own choice")
		a.expectNothing(t, 100*time.Millisecond)
		if hop := b.current("A"); hop != "R1" {
			t.Fatalf("B's own choice is %q, want R1", hop)
		}
		a.send(t, toB, "latest")
		latest := b.expect(t, "latest")
		b.send(t, latest.ep, "followed")
		a.expect(t, "followed")
		if hop := b.current("A"); hop != "R2" {
			t.Fatalf("B follows A through %q, want R2", hop)
		}
	})
}

// The policy as of TP-006 (TP-031 decides the final one): a pair that
// failed over stays on the backup for the hold-down after the primary is
// back; then the leader returns to the primary and the follower comes along.
func TestAFailedOverPairReturnsAfterTheHoldDown(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB := a.endpoint(t, "B")
		traffic := func() { exchange(a, b, toB, wgMsg("traffic")) }
		f.silence("A", "R1", true)
		f.silence("B", "R1", true)
		f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, traffic)
		if aHop, bHop := pingPong(t, a, b, toB, "failed over"); aHop != "R2" || bHop != "R2" {
			t.Fatalf("after R1 died: A on %q, B on %q, want R2", aHop, bHop)
		}

		f.silence("A", "R1", false)
		f.silence("B", "R1", false)
		f.waitUp("A", "R1")
		f.waitUp("B", "R1")
		s, _ := f.neighbor("A", "R1")
		hold := 10*time.Second - s.UpFor // what is left of fakeOptions' hold-down
		var elapsed, aBack time.Duration
		f.advance(hold+2*time.Second, func() {
			elapsed += fakeStep
			aHop, bHop := pingPong(t, a, b, toB, "traffic")
			switch {
			case aBack == 0 && aHop == "R1":
				aBack = elapsed
			case aBack == 0 && bHop != "R2":
				t.Fatalf("%v after R1 came back, B left the backup before A: on %q", elapsed, bHop)
			case aBack != 0 && elapsed > aBack+fakeStep && bHop != "R1":
				t.Fatalf("B stays on %q after A returned to R1", bHop)
			}
		})
		if aBack < hold || aBack > hold+2*fakeStep {
			t.Fatalf("A returned to R1 %v later, want just after the %v left of the hold-down", aBack, hold)
		}
	})
}

// A first hop whose own links are fine but that can't reach the peer: the
// Bind demotes it after E2EDead of unanswered handshakes, tries it again
// after the hold-down, and demotes it for twice as long the second time.
func TestUnansweredHandshakesDemoteAFirstHop(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB := a.endpoint(t, "B")
		pingPong(t, a, b, toB, "before")
		// R1 loses B; A's links to R1 stay up.
		f.silence("B", "R1", true)
		f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, nil)
		b.drain()
		if !f.isUp("A", "R1") {
			t.Fatal("A's link to R1 went down; the test needs it up")
		}

		var elapsed time.Duration
		var switches []time.Duration
		hop := a.current("B")
		f.advance(30*time.Second, func() {
			elapsed += fakeStep
			if now, _ := exchange(a, b, toB, wgInitiation()); now != hop {
				hop = now
				switches = append(switches, elapsed)
			}
		})
		e2e, hold := f.opts.E2EDead, 10*time.Second
		want := []time.Duration{e2e, 2*e2e + hold, 3*e2e + hold}
		if len(switches) != len(want) {
			t.Fatalf("switched at %v, want about %v", switches, want)
		}
		for i := range want {
			if switches[i] < want[i] || switches[i] > want[i]+4*fakeStep {
				t.Fatalf("switch %d at %v, want just after %v (all: %v)", i, switches[i], want[i], switches)
			}
		}
		if hop != "R2" || f.node("A").Counters().Demotions != 2 {
			t.Fatalf("ends on %q with %d demotions, want R2 and 2", hop, f.node("A").Counters().Demotions)
		}
	})
}

// Data alone waits for WireGuard's keepalive too: a peer that only
// receives answers within 10 s.
func TestUnansweredDataDemotesAFirstHopLater(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB := a.endpoint(t, "B")
		pingPong(t, a, b, toB, "before")
		f.silence("B", "R1", true)
		f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, nil)

		var elapsed, switched time.Duration
		f.advance(f.opts.E2EDead+12*time.Second, func() {
			elapsed += fakeStep
			_ = a.Send([][]byte{wgMsg("data")}, toB)
			if switched == 0 && a.current("B") == "R2" {
				switched = elapsed
			}
		})
		want := f.opts.E2EDead + 10*time.Second
		if switched < want || switched > want+4*fakeStep {
			t.Fatalf("switched after %v of unanswered data, want just after %v", switched, want)
		}
	})
}

// In the middle of a chain a relay follows the path the destination's
// packets come through when the destination leads the pair, and picks by
// its own order when the source leads.
func TestMidChainRelayFollowsTheLeadingEnd(t *testing.T) {
	for _, tc := range []struct {
		exit, want string
	}{
		{exit: "C", want: "M2"}, // C < D: the exit leads with its own order, M2 first
		{exit: "Z", want: "M1"}, // D < Z: the device's side leads; N keeps its own order
	} {
		t.Run(tc.exit, func(t *testing.T) {
			f := newFakeFabric(t, 0)
			x := tc.exit
			f.add("D", "N", "M1", "M2", x)
			f.dial("D", "N")
			for _, m := range []string{"M1", "M2"} {
				f.dial("N", m)
				f.dial(m, x)
				f.route(m, x, x)
				f.route(m, "D", "N")
			}
			f.route("N", x, "M1", "M2")
			f.route("N", "D", "D")
			d := f.bind("D", peer(x, "N"))
			e := f.bind(x, peer("D", "M2", "M1"))
			toX := d.endpoint(t, x)
			for i := range 20 {
				f.clock.add(fakeStep)
				d.send(t, toX, "to the exit")
				got := e.expect(t, "to the exit")
				e.send(t, got.ep, "back")
				d.expect(t, "back")
				if i < 2 {
					continue
				}
				hop, _, _ := f.node("N").Route(id(x))
				if hop != id(tc.want) {
					t.Fatalf("round %d: N relays to %s through %s, want %s", i, x, hop, tc.want)
				}
			}
		})
	}
}

// B, the follower, loses R1 while A's link to R1 stays up: A keeps
// sending into R1, which can't reach B, while B talks through R2. A must
// notice within E2EDead and move to R2.
func TestTheLeaderLeavesAHopTheFollowerCantUse(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB, toA := a.endpoint(t, "B"), b.endpoint(t, "A")
		pingPong(t, a, b, toB, "before")
		f.silence("B", "R1", true)
		var elapsed, switched time.Duration
		f.advance(f.opts.DeadAfter+3*f.opts.E2EDead, func() {
			elapsed += fakeStep
			_ = b.Send([][]byte{wgMsg("B's own traffic")}, toA)
			exchange(a, b, toB, wgMsg("A's traffic"))
			if switched == 0 && a.current("B") == "R2" {
				switched = elapsed
			}
		})
		if !f.isUp("A", "R1") {
			t.Fatal("A's link to R1 went down; the test needs it up")
		}
		// B's own link to R1 dies after DeadAfter; from then on B talks
		// through R2 and A should be gone from R1 within E2EDead.
		limit := f.opts.DeadAfter + f.opts.E2EDead + f.opts.ProbeInterval
		if switched == 0 || switched > limit {
			t.Fatalf("A moved to R2 after %v, want within %v", switched, limit)
		}
		if aHop, bHop := pingPong(t, a, b, toB, "after"); aHop != "R2" || bHop != "R2" {
			t.Fatalf("A on %q, B on %q, want R2", aHop, bHop)
		}
	})
}
