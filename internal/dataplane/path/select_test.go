package path_test

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
)

func TestFailover(t *testing.T) {
	const hold = 10 * time.Second
	up := func(name string, upFor time.Duration) path.Candidate {
		return path.Candidate{Hop: id(name), Up: true, UpFor: upFor, Linked: true}
	}
	down := func(name string) path.Candidate { return path.Candidate{Hop: id(name), Linked: true} }
	followed := func(c path.Candidate) path.Candidate { c.Followed = true; return c }

	for _, tc := range []struct {
		name    string
		current string
		cands   []path.Candidate
		want    string // "" for none
	}{
		{"first up in priority order", "", []path.Candidate{down("R1"), up("R2", 0), up("R3", hold)}, "R2"},
		{"keeps the current hop while it is up", "R2", []path.Candidate{up("R1", hold-1), up("R2", 0)}, "R2"},
		{"returns to an earlier hop after the hold-down", "R3", []path.Candidate{up("R1", hold), up("R2", hold), up("R3", hold)}, "R1"},
		{"leaves a current hop that went down", "R1", []path.Candidate{down("R1"), up("R2", 0)}, "R2"},
		{"follows the peer's path", "R1", []path.Candidate{up("R1", hold), followed(up("R2", 0))}, "R2"},
		{"doesn't follow onto a hop that is down here", "R1", []path.Candidate{up("R1", hold), followed(down("R2"))}, "R1"},
		{"tries a link not heard from yet", "", []path.Candidate{{Hop: id("R1")}, down("R2")}, "R2"},
		{"nothing usable", "R1", []path.Candidate{{Hop: id("R1")}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current path.NodeID
			if tc.current != "" {
				current = id(tc.current)
			}
			got, ok := path.Failover{HoldDown: hold}.Select(current, tc.cands)
			switch {
			case tc.want == "" && ok:
				t.Fatalf("picked %s, want none", got)
			case tc.want != "" && (!ok || got != id(tc.want)):
				t.Fatalf("picked %s (%v), want %s", got, ok, tc.want)
			}
		})
	}
}

// A primary that flaps faster than the hold-down never takes traffic back.
func TestFailoverDoesNotFlap(t *testing.T) {
	const hold = 10 * time.Second
	sel := path.Failover{HoldDown: hold}
	rng := rand.New(rand.NewPCG(1, 2))
	current := id("R2")
	var primaryUpFor time.Duration
	switches := 0
	for range 10000 {
		step := time.Duration(rng.IntN(3000)) * time.Millisecond
		primary := path.Candidate{Hop: id("R1"), Linked: true}
		if rng.IntN(4) > 0 { // up three steps in four, never 10 s in a row
			primaryUpFor += step
			primary.Up, primary.UpFor = true, primaryUpFor
		} else {
			primaryUpFor = 0
		}
		if primary.UpFor >= hold {
			primaryUpFor = 0 // a jittery primary: drops before the hold-down
			primary.Up, primary.UpFor = false, 0
		}
		backup := path.Candidate{Hop: id("R2"), Up: true, UpFor: time.Hour, Linked: true}
		got, ok := sel.Select(current, []path.Candidate{primary, backup})
		if !ok {
			t.Fatal("no hop picked")
		}
		if got != current {
			switches++
			current = got
		}
	}
	if switches != 0 {
		t.Fatalf("switched %d times between a flapping primary and a steady backup", switches)
	}
}
