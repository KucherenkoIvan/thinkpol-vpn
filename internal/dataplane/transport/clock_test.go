package transport

import (
	"testing"
	"time"
)

// The sealed time wraps in 2106; freshness holds across the wrap, either
// way round, and ends at MaxClockSkew.
func TestFreshUnix(t *testing.T) {
	wrap := time.Unix(1<<32, 0)
	for _, at := range []time.Time{time.Unix(1_800_000_000, 0), wrap.Add(-10 * time.Second), wrap.Add(10 * time.Second)} {
		sent := uint32(at.Unix())
		for _, skew := range []time.Duration{0, 20 * time.Second, -20 * time.Second, MaxClockSkew, -MaxClockSkew} {
			if !FreshUnix(sent, at.Add(skew)) {
				t.Errorf("sent %v, received %v later: stale", at.UTC(), skew)
			}
		}
		for _, skew := range []time.Duration{MaxClockSkew + time.Second, -MaxClockSkew - time.Second, 24 * time.Hour, -24 * time.Hour} {
			if FreshUnix(sent, at.Add(skew)) {
				t.Errorf("sent %v, received %v later: fresh", at.UTC(), skew)
			}
		}
	}
}

// A narrower window ends where it says, either way round.
func TestFreshWithinEndsAtItsWindow(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	sent := uint32(at.Unix())
	if !FreshWithin(sent, at.Add(-time.Minute), time.Minute) || FreshWithin(sent, at.Add(61*time.Second), time.Minute) {
		t.Error("a one-minute window doesn't end at a minute")
	}
}
