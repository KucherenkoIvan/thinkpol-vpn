package clockburst

import (
	"testing"
	"time"
)

func TestWindowResetsAfterQuiet(t *testing.T) {
	w := NewWindow(time.Minute)
	now := time.Unix(1_800_000_000, 0)
	w.Add(2, now)
	if w.Count(now) != 2 {
		t.Fatalf("count %d", w.Count(now))
	}
	if w.Count(now.Add(2*time.Minute)) != 0 {
		t.Fatal("window did not expire")
	}
	w.Add(1, now.Add(2*time.Minute))
	if w.Count(now.Add(2*time.Minute)) != 1 {
		t.Fatal("new window")
	}
}
