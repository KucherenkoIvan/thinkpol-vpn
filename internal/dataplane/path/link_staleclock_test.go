package path

import (
	"testing"
	"time"
)

func TestFoldStaleClock(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	n, err := NewNode(NodeID{1}, Options{Now: func() time.Time { return now }, DeadAfter: 2 * time.Hour, ProbeInterval: time.Hour, watchEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var staleN uint64 = 3
	l := &link{node: n, staleClock: func() uint64 { return staleN }}
	l.foldStaleClock()
	if n.Counters().StaleClock != 3 {
		t.Fatalf("first fold: %d", n.Counters().StaleClock)
	}
	staleN = 5
	l.foldStaleClock()
	if n.Counters().StaleClock != 5 {
		t.Fatalf("after second fold: %d", n.Counters().StaleClock)
	}
	staleN = 5
	if got := n.Counters().StaleClock; got != 5 {
		t.Fatalf("counters: %d", got)
	}
}
