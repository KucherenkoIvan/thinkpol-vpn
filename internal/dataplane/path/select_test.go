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

	const lead, follow = false, true
	for _, tc := range []struct {
		name    string
		follows bool
		current string
		cands   []path.Candidate
		want    string // "" for none
	}{
		{"first up in priority order", lead, "", []path.Candidate{down("R1"), up("R2", 0), up("R3", hold)}, "R2"},
		{"keeps the current hop while it is up", lead, "R2", []path.Candidate{up("R1", hold-1), up("R2", 0)}, "R2"},
		{"returns to an earlier hop after the hold-down", lead, "R3", []path.Candidate{up("R1", hold), up("R2", hold), up("R3", hold)}, "R1"},
		{"leaves a current hop that went down", lead, "R1", []path.Candidate{down("R1"), up("R2", 0)}, "R2"},
		{"a leader never follows", lead, "R1", []path.Candidate{up("R1", hold), followed(up("R2", 0))}, "R1"},
		{"a follower follows", follow, "R1", []path.Candidate{up("R1", hold), followed(up("R2", 0))}, "R2"},
		{"not onto a hop that is down here", follow, "R1", []path.Candidate{up("R1", hold), followed(down("R2"))}, "R1"},
		{"a follower never returns on its own", follow, "R2", []path.Candidate{up("R1", time.Hour), up("R2", 0)}, "R2"},
		{"a follower leaves a hop that went down", follow, "R2", []path.Candidate{up("R1", 0), down("R2")}, "R1"},
		{"tries a link not proven yet", lead, "", []path.Candidate{{Hop: id("R1")}, down("R2")}, "R2"},
		{"nothing usable", lead, "R1", []path.Candidate{{Hop: id("R1")}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var current path.NodeID
			if tc.current != "" {
				current = id(tc.current)
			}
			got, ok := path.Failover{HoldDown: hold}.Select(path.Choice{Current: current, Follows: tc.follows, Candidates: tc.cands})
			switch {
			case tc.want == "" && ok:
				t.Fatalf("picked %s, want none", got)
			case tc.want != "" && (!ok || got != id(tc.want)):
				t.Fatalf("picked %s (%v), want %s", got, ok, tc.want)
			}
		})
	}
}

// A primary that comes and goes: traffic returns to it only once it has
// been up for the hold-down, then and not later, and leaves it only when it
// goes down.
func TestFailoverHysteresis(t *testing.T) {
	const hold = 10 * time.Second
	sel := path.Failover{HoldDown: hold}
	rng := rand.New(rand.NewPCG(1, 2))
	backup := path.Candidate{Hop: id("R2"), Up: true, UpFor: time.Hour, Linked: true}
	current := id("R2")
	primary := path.Candidate{Hop: id("R1"), Linked: true}
	returns, leaves := 0, 0
	for step := range 20000 {
		// Runs of up and down average 10 s in 500 ms steps: some outlast
		// the hold-down, most don't.
		if rng.IntN(20) == 0 {
			primary.Up = !primary.Up
			primary.UpFor = 0
		} else if primary.Up {
			primary.UpFor += 500 * time.Millisecond
		}
		got, ok := sel.Select(path.Choice{Current: current, Candidates: []path.Candidate{primary, backup}})
		if !ok {
			t.Fatal("no hop picked")
		}
		switch {
		case got == current:
			if current == id("R2") && primary.Up && primary.UpFor >= hold {
				t.Fatalf("step %d: stayed on the backup with the primary up for %v", step, primary.UpFor)
			}
			if current == id("R1") && !primary.Up {
				t.Fatalf("step %d: stayed on a primary that is down", step)
			}
		case got == id("R1"):
			if !primary.Up || primary.UpFor < hold {
				t.Fatalf("step %d: returned to the primary after %v up", step, primary.UpFor)
			}
			returns++
		default:
			if primary.Up {
				t.Fatalf("step %d: left the primary while it was up", step)
			}
			leaves++
		}
		current = got
	}
	if returns == 0 || leaves == 0 {
		t.Fatalf("%d returns and %d departures: the run tested nothing", returns, leaves)
	}
	t.Logf("%d returns to the primary, %d departures", returns, leaves)
}
