package firewall

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// An anchor nothing evaluates guards nothing: without the main ruleset's
// hook (the system hasn't loaded /etc/pf.conf yet at boot, or it was
// replaced) the guard fails as any retried failure does, never
// unsupported, and loads and enables nothing; it is whole once the hook is
// there, however late.
func TestWithoutTheAppleHookTheGuardWaitsForIt(t *testing.T) {
	for _, main := range [][]string{
		nil, // not loaded yet, or the main ruleset flushed
		{`scrub-anchor "com.apple/*" all fragment reassemble`},
		{`anchor "com.apple/*" in all`},
		{`pass out all`, `anchor "other/*" all`},
	} {
		r := newRig(t)
		r.pf.main = main
		g := r.guard()
		e := exempt(t)
		for range 3 { // retried, and still failing as an ordinary failure
			err := g.Apply(context.Background(), e)
			if err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
				t.Fatalf("%q: %v, want an ordinary failure", main, err)
			}
		}
		if n := r.pf.ran("-f") + r.pf.ran("-E"); n != 0 || r.pf.isOn() {
			t.Fatalf("%q: loaded or enabled %d times, pf on %v", main, n, r.pf.isOn())
		}
		r.pf.set(func(f *fakePF) { f.main = stockMain })
		if err := g.Apply(context.Background(), e); err != nil {
			t.Fatalf("%q, then the hook: %v", main, err)
		}
		r.whole(t, e)
	}
}

// The hook going away under an applied guard fails it, retried, and it is
// whole again once the hook is back; Close still removes it all.
func TestTheHookGoingAwayIsRetried(t *testing.T) {
	r := newRig(t)
	g := r.guard()
	e := exempt(t)
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.pf.set(func(f *fakePF) { f.main = nil })
	if err := g.Apply(context.Background(), e); err == nil || errors.Is(err, routetable.ErrGuardUnsupported) {
		t.Errorf("%v, want an ordinary failure", err)
	}
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	r.whole(t, e)
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.gone(t)
}

// Through the route table: the routes go in at once, the guard reads as
// failing (not unsupported, which would stop it for good), and the route
// table puts it in once the hook is there, on the guard's own poll.
func TestTheRouteTableTakesTheGuardOnceTheHookIsThere(t *testing.T) {
	r := newRig(t)
	r.pf.main = nil
	g := newIPv6Guard(r.pf, r.store(), 10*time.Millisecond, ownAddrs)
	enf := routetable.OpenWithGuard(routesOnly{}, g, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = enf.Close() }()
	w := routetable.Want{TUN: "utun7", Direct: set(t, "2001:db8:d0::/48"), Upstreams: aps("[2001:db8:53::1]:53")}
	if err := enf.Enforce(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	// routesOnly shows no TUN, so the routes read as down, but they are in.
	if st := enf.Status(); st.Routes == 0 || st.GuardEnforced || st.GuardError != routetable.ErrorGuard {
		t.Fatalf("status %+v, want the routes and %s", st, routetable.ErrorGuard)
	}
	r.pf.set(func(f *fakePF) { f.main = stockMain })
	for deadline := time.Now().Add(10 * time.Second); !enf.Status().GuardEnforced && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if st := enf.Status(); !st.GuardEnforced || st.GuardError != "" || !r.pf.isOn() {
		t.Errorf("after the hook was loaded: %+v, pf on %v", st, r.pf.isOn())
	}
}
