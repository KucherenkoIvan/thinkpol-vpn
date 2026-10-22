package firewall

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// upFor is a clock of the time since the boot that a test moves.
type upFor struct{ d atomic.Int64 }

func (u *upFor) set(d time.Duration)               { u.d.Store(int64(d)) }
func (u *upFor) sinceBoot() (time.Duration, error) { return time.Duration(u.d.Load()), nil }

// An agent the service starts early in a boot may find pf's main ruleset
// without the hook, because the system hasn't loaded /etc/pf.conf yet:
// the guard fails as it would for any retried failure, loads and enables
// nothing, and is whole once the hook is there. Past the grace the same
// main ruleset is unsupported, as before.
func TestEarlyInABootAMissingHookIsRetried(t *testing.T) {
	r := newRig(t)
	r.pf.main = nil // not loaded yet
	var up upFor
	up.set(20 * time.Second)
	g := r.guard()
	g.sinceBoot = up.sinceBoot
	e := exempt(t)
	err := g.Apply(context.Background(), e)
	if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Fatalf("%v, want an ordinary failure", err)
	}
	if n := r.pf.ran("-f") + r.pf.ran("-E"); n != 0 || r.pf.isOn() {
		t.Fatalf("loaded or enabled %d times, pf on %v", n, r.pf.isOn())
	}
	up.set(40 * time.Second)
	r.pf.set(func(f *fakePF) { f.main = stockMain }) // the system loaded it
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e)

	// Past the grace, a hook still missing is the guard unsupported.
	r = newRig(t)
	r.pf.main = nil
	up.set(4 * time.Minute)
	g = r.guard()
	g.sinceBoot = up.sinceBoot
	if err := g.Apply(context.Background(), e); err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Fatalf("%v, want an ordinary failure", err)
	}
	up.set(bootGrace)
	if err := g.Apply(context.Background(), e); !errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Fatalf("%v, want unsupported", err)
	}
}

// Through the route table: the routes go in at once, the guard reads as
// failing (not unsupported, which stops it for good), and the route table
// puts it in once the system has loaded the hook, on the guard's own poll.
func TestTheRouteTableTakesTheGuardOnceTheBootLoadedTheHook(t *testing.T) {
	for _, early := range []bool{true, false} {
		r := newRig(t)
		r.pf.main = nil
		g := newIPv6Guard(r.pf, r.store(), 10*time.Millisecond, ownAddrs)
		var up upFor
		up.set(time.Hour)
		if early {
			up.set(30 * time.Second)
		}
		g.sinceBoot = up.sinceBoot
		enf := routetable.OpenWithGuard(routesOnly{}, g, slog.New(slog.NewTextHandler(io.Discard, nil)))
		w := routetable.Want{TUN: "utun7", Direct: set(t, "2001:db8:d0::/48"), Upstreams: aps("[2001:db8:53::1]:53")}
		if err := enf.Enforce(context.Background(), w); err != nil {
			t.Fatal(err)
		}
		st := enf.Status()
		wantErr := routetable.ErrorGuardUnsupported
		if early {
			wantErr = routetable.ErrorGuard
		}
		// routesOnly shows no TUN, so the routes read as down, but they
		// are in.
		if st.Routes == 0 || st.GuardEnforced || st.GuardError != wantErr {
			t.Fatalf("early %v: status %+v, want the routes and %s", early, st, wantErr)
		}
		r.pf.set(func(f *fakePF) { f.main = stockMain })
		// Early: until the poll's retry puts the guard in. Past the grace:
		// a window of some thirty polls in which nothing may happen.
		wait := 300 * time.Millisecond
		if early {
			wait = 10 * time.Second
		}
		for deadline := time.Now().Add(wait); !enf.Status().GuardEnforced && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		st = enf.Status()
		if early && (!st.GuardEnforced || st.GuardError != "" || !r.pf.isOn()) {
			t.Errorf("after the hook was loaded: %+v, pf on %v", st, r.pf.isOn())
		}
		if !early && (st.GuardEnforced || st.GuardError != routetable.ErrorGuardUnsupported) {
			t.Errorf("unsupported past the grace, then: %+v", st)
		}
		if err := enf.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// The host's guard knows how long ago the system booted: Darwin's
// monotonic clock, which counts from the boot, against kern.boottime (a
// wall-clock time, so within a margin for clock steps).
func TestTheHostGuardKnowsTheTimeSinceTheBoot(t *testing.T) {
	g := NewIPv6Guard()
	if g.sinceBoot == nil {
		t.Fatal("no clock since the boot")
	}
	up, err := g.sinceBoot()
	if err != nil {
		t.Fatal(err)
	}
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		t.Fatal(err)
	}
	wall := time.Since(time.Unix(tv.Unix()))
	if d := wall - up; d < -10*time.Minute || d > 10*time.Minute {
		t.Fatalf("since the boot %v, kern.boottime says %v", up, wall)
	}
}
