package path_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
)

// unreachable fails every dial while down is set, as with no route to the
// far end, and dials over the fabric's network otherwise.
type unreachable struct {
	f    *fabric
	down *atomic.Bool
}

func (d unreachable) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	if d.down.Load() {
		return nil, errors.New("no route to host")
	}
	return d.f.tr.Dial(ctx, endpoint, cfg)
}

// unanswered holds every dial until open is closed, as a far end that
// hasn't answered a handshake yet, then dials over the fabric's network.
type unanswered struct {
	f    *fabric
	open chan struct{}
}

func (d unanswered) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.open:
	}
	return d.f.tr.Dial(ctx, endpoint, cfg)
}

// dialB makes A dial B through dialer.
func dialB(f *fabric, dialer transport.Dialer) *fnode {
	f.add("A", "B")
	secret := f.accept("B", "A", transport.SpaceID{})
	a := f.node("A")
	a.table.Links = []path.Link{{Node: id("B"), Endpoints: []path.Endpoint{{
		Transport: memory.Name, Dialer: dialer, Address: "B",
		Config: transport.DialConfig{Credential: secret},
	}}}}
	a.Update(a.table)
	return a
}

// wantDownNoLinks fails unless B is listed at A as dialed, down, no links.
func wantDownNoLinks(t *testing.T, f *fabric) {
	t.Helper()
	s, ok := f.neighbor("A", "B")
	switch {
	case !ok:
		t.Fatal("B, dialed with no link, isn't listed")
	case s.Up || !s.Dialed || len(s.Links) != 0:
		t.Fatalf("B = %+v, want dialed, down, no links", s)
	}
}

// waitUpOnce waits for B up at A and checks it is listed once.
func waitUpOnce(t *testing.T, f *fabric, a *fnode) {
	t.Helper()
	f.waitUp("A", "B")
	listed := 0
	for _, s := range a.Neighbors() {
		if s.Node == id("B") {
			listed++
		}
	}
	if listed != 1 {
		t.Fatalf("B, linked, is listed %d times", listed)
	}
}

// A dial that has failed lists the node, down, at once: the fake clock
// never moves, so DeadAfter can't be what lists it.
func TestNeighborsListAFailedDialAtOnce(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		var down atomic.Bool
		down.Store(true)
		a := dialB(f, unreachable{f: f, down: &down})
		eventually(t, "B is listed after a failed dial", func() bool { _, ok := f.neighbor("A", "B"); return ok })
		wantDownNoLinks(t, f)

		down.Store(false)
		waitUpOnce(t, f, a)
	})
}

// A dial still waiting for an answer isn't listed until DeadAfter has
// passed since it started; then it is, down; a link that comes up shows it up.
func TestNeighborsListAnUnansweredDialPastDeadAfter(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		open := make(chan struct{})
		a := dialB(f, unanswered{f: f, open: open})

		f.advance(fakeOptions.DeadAfter-2*fakeStep, nil)
		if s, ok := f.neighbor("A", "B"); ok {
			t.Fatalf("B is listed before DeadAfter: %+v", s)
		}
		f.advance(2*fakeStep, nil)
		wantDownNoLinks(t, f)

		close(open)
		waitUpOnce(t, f, a)
	})
}
