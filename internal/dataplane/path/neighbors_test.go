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

// A node dialed with no link yet is listed, down, once it has been dialed
// for DeadAfter, not before; a link that comes up shows it up.
func TestNeighborsListADialThatNeverLinkedPastDeadAfter(t *testing.T) {
	eachSemanticsFake(t, func(t *testing.T, f *fabric) {
		f.add("A", "B")
		secret := f.accept("B", "A", transport.SpaceID{})
		var down atomic.Bool
		down.Store(true)
		a := f.node("A")
		a.table.Links = []path.Link{{Node: id("B"), Endpoints: []path.Endpoint{{
			Transport: memory.Name, Dialer: unreachable{f: f, down: &down}, Address: "B",
			Config: transport.DialConfig{Credential: secret},
		}}}}
		a.Update(a.table)

		f.advance(fakeOptions.DeadAfter-2*fakeStep, nil)
		if s, ok := f.neighbor("A", "B"); ok {
			t.Fatalf("B is listed before DeadAfter: %+v", s)
		}
		f.advance(2*fakeStep, nil)
		s, ok := f.neighbor("A", "B")
		switch {
		case !ok:
			t.Fatal("B, dialed for DeadAfter with no link, isn't listed")
		case s.Up || !s.Dialed || len(s.Links) != 0:
			t.Fatalf("B = %+v, want dialed, down, no links", s)
		}

		down.Store(false)
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
	})
}
