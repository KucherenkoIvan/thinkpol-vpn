//go:build linux && !android

package firewall

import (
	"testing"
	"time"

	"github.com/google/nftables"
)

// Only the direct sets expire, after DirectTimeout unless the kill switch
// was given another timeout; a new one rebuilds the table at the next
// Apply, since a renewal keeps the sets it finds.
func TestKillSwitchDirectTimeout(t *testing.T) {
	timeouts := func(k *KillSwitch) map[string]time.Duration {
		got := map[string]time.Duration{}
		for _, s := range killSwitchSets(&nftables.Table{Name: KillSwitchTable}, KillSwitchRules{}, k.expiry()) {
			if s.set.HasTimeout {
				got[s.set.Name] = s.set.Timeout
			}
		}
		return got
	}
	k := NewKillSwitch()
	if got := timeouts(k); len(got) != 2 || got[directSet4] != DirectTimeout || got[directSet6] != DirectTimeout {
		t.Errorf("by default: %v, want direct4 and direct6 after %v", got, DirectTimeout)
	}
	k.applied = &KillSwitchRules{}
	k.SetDirectTimeout(3 * time.Second)
	if got := timeouts(k); len(got) != 2 || got[directSet4] != 3*time.Second || got[directSet6] != 3*time.Second {
		t.Errorf("set to 3 s: %v", got)
	}
	if k.applied != nil {
		t.Error("a new timeout would be renewed into the sets in place")
	}
	k.applied = &KillSwitchRules{}
	k.SetDirectTimeout(3 * time.Second)
	if k.applied == nil {
		t.Error("the same timeout again rebuilds the table")
	}
	// nftables reads a negative timeout as unsigned (about 2^64 ms) and
	// keeps whole milliseconds: under 1 ms is 0, a set that never expires.
	wrapped := 855000 * time.Hour
	wrapped *= 3
	for _, d := range []time.Duration{-time.Second, wrapped, 0, time.Nanosecond, 999 * time.Microsecond} {
		k.SetDirectTimeout(d)
		if got := timeouts(k); got[directSet4] != DirectTimeout || got[directSet6] != DirectTimeout {
			t.Errorf("set to %v: %v, want %v", d, got, DirectTimeout)
		}
	}
	k.SetDirectTimeout(time.Millisecond)
	if got := timeouts(k); got[directSet4] != time.Millisecond || got[directSet6] != time.Millisecond {
		t.Errorf("set to 1 ms: %v", got)
	}
	if DirectTimeout != 30*time.Second {
		t.Errorf("DirectTimeout is %v, the design's 30 s", DirectTimeout)
	}
}
