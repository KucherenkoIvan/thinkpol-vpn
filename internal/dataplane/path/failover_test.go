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
		keepSending(t, a, b, toB, "before")
		reachesHop(t, a, toB, "B", "R1")

		// R1 dies without a word: nothing reports it, its links just go quiet.
		f.silence("A", "R1", true)
		f.silence("B", "R1", true)
		start := time.Now()
		got := keepSending(t, a, b, toB, "after")
		took := time.Since(start)
		reachesHop(t, a, toB, "B", "R2")
		keepSending(t, b, a, got.ep, "and back")
		reachesHop(t, b, got.ep, "A", "R2")
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
		keepSending(t, a, b, toB, "before")
		reachesHop(t, a, toB, "B", "R1")
		_ = f.node("R1").Close()
		keepSending(t, a, b, toB, "after")
		reachesHop(t, a, toB, "B", "R2")
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

// The follower never returns to its primary on its own: after the pair
// failed over and the primary came back, a follower that hears nothing from
// the leader for longer than FollowFor and then talks stays on the backup.
func TestAnIdleFollowerDoesNotSwitchBack(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		a, b := twoRelays(t, f, r1r2, r1r2)
		toB, toA := a.endpoint(t, "B"), b.endpoint(t, "A")
		f.silence("A", "R1", true)
		f.silence("B", "R1", true)
		f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, func() { exchange(a, b, toB, wgMsg("traffic")) })
		if aHop, bHop := pingPong(t, a, b, toB, "failed over"); aHop != "R2" || bHop != "R2" {
			t.Fatalf("after R1 died: A on %q, B on %q, want R2", aHop, bHop)
		}
		f.silence("A", "R1", false)
		f.silence("B", "R1", false)
		f.waitUp("B", "R1")

		f.advance(fakeHold+f.opts.FollowFor+time.Second, nil) // nothing from A
		b.send(t, toA, "B talks first")
		a.await(t, "B talks first")
		if hop := b.current("A"); hop != "R2" {
			t.Fatalf("idle follower went back to %q on its own, want R2", hop)
		}
	})
}

// Traffic one way only, either way, survives losing the first hop: the
// sender fails over on its own links, and the receiver needs nothing.
func TestOneWayFlowsFailOver(t *testing.T) {
	for _, dir := range []struct{ name, from, to string }{{"leader to follower", "A", "B"}, {"follower to leader", "B", "A"}} {
		t.Run(dir.name, func(t *testing.T) {
			f := newFakeFabric(t, 0)
			a, b := twoRelays(t, f, r1r2, r1r2)
			from, to := a, b
			if dir.from == "B" {
				from, to = b, a
			}
			ep := from.endpoint(t, dir.to)
			from.send(t, ep, "before")
			to.await(t, "before")
			f.silence("A", "R1", true)
			f.silence("B", "R1", true)
			f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, func() { _ = from.Send([][]byte{wgMsg("lost")}, ep) })
			from.send(t, ep, "after")
			to.await(t, "after")
			if hop := from.current(dir.to); hop != "R2" {
				t.Fatalf("%s sends through %q, want R2", dir.from, hop)
			}
		})
	}
}

// A link that delivers only one way is down for both ends: here the
// accepting end's packets are lost on the way, and its probes go
// unanswered.
func TestOneWayLossOnAnAcceptedLinkIsDetected(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		f.add("A", "R")
		f.dial("A", "R")
		f.waitUp("R", "A")
		f.silenceInbound("A", "R") // what R sends to A is lost
		var elapsed, down time.Duration
		f.advance(f.opts.DeadAfter+time.Second, func() {
			elapsed += fakeStep
			if down == 0 && !f.isUp("R", "A") {
				down = elapsed
			}
		})
		o := f.opts
		if down == 0 || down < o.DeadAfter-o.ProbeInterval-2*fakeStep || down > o.DeadAfter+2*fakeStep {
			t.Fatalf("R saw its link to A down %v after the loss began, want about DeadAfter (%v)", down, o.DeadAfter)
		}
	})
}

// In the middle of a chain a relay keeps one next hop per destination,
// whatever the ends choose, and fails over on its own links with the
// hold-down: no following, no alternation.
func TestMidChainRelayFailsOverOnItsOwnLinks(t *testing.T) {
	f := newFakeFabric(t, 0)
	f.add("D", "N", "M1", "M2", "C")
	f.dial("D", "N")
	for _, m := range []string{"M1", "M2"} {
		f.dial("N", m)
		f.dial(m, "C")
		f.route(m, "C", "C")
		f.route(m, "D", "N")
	}
	f.route("N", "C", "M1", "M2")
	f.route("N", "D", "D")
	d := f.bind("D", peer("C", "N"))
	c := f.bind("C", peer("D", "M2", "M1")) // the exit prefers the other middle
	toC := d.endpoint(t, "C")
	round := func(tag string) string {
		t.Helper()
		d.send(t, toC, tag)
		got := c.await(t, tag)
		c.send(t, got.ep, tag+" back")
		d.await(t, tag+" back")
		hop, _, _ := f.node("N").Route(id("C"))
		return string(trimID(hop))
	}
	for i := range 20 {
		if hop := round("steady"); hop != "M1" {
			t.Fatalf("round %d: N relays to C through %s, want M1 throughout", i, hop)
		}
	}
	if m2 := f.node("M2").Counters().Forwarded; m2 != 20 {
		t.Fatalf("M2 forwarded %d, want only C's 20 replies", m2)
	}

	f.silence("N", "M1", true)
	f.advance(f.opts.DeadAfter+f.opts.ProbeInterval, func() { _ = d.Send([][]byte{wgMsg("lost")}, toC) })
	if hop := round("failed over"); hop != "M2" {
		t.Fatalf("after N lost M1: through %s, want M2", hop)
	}
	f.silence("N", "M1", false)
	f.waitUp("N", "M1")
	f.advance(fakeHold-time.Second, func() { round("held") })
	if hop := round("held"); hop != "M2" {
		t.Fatalf("N went back to %s before the hold-down", hop)
	}
	f.advance(2*time.Second, func() { round("back") })
	if hop := round("back"); hop != "M1" {
		t.Fatalf("after the hold-down N relays through %s, want M1", hop)
	}
}
