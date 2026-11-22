package main

import (
	"testing"
	"time"
)

// TestLabKillSwitchReapply: the kill switch's timing changes only in a lab
// node, only to a shorter period of at least a second; anything else is
// the defaults.
func TestLabKillSwitchReapply(t *testing.T) {
	for _, c := range []struct {
		lab, reapply string
		want         time.Duration
	}{
		{"1", "2s", 2 * time.Second},
		{"1", "1s", time.Second},
		{"", "2s", 0},
		{"0", "2s", 0},
		{"1", "", 0},
		{"1", "two", 0},
		{"1", "500ms", 0},
		{"1", "10s", 0},
		{"1", "1h", 0},
		{"1", "855h", 0},
		{"1", "855000h", 0},  // three times it wraps negative
		{"1", "1000000h", 0}, // likewise
	} {
		env := map[string]string{"THINKPOL_LAB": c.lab, "THINKPOL_LAB_KILL_SWITCH_REAPPLY": c.reapply}
		if got := labKillSwitchReapply(func(k string) string { return env[k] }); got != c.want {
			t.Errorf("THINKPOL_LAB=%q THINKPOL_LAB_KILL_SWITCH_REAPPLY=%q: %v, want %v", c.lab, c.reapply, got, c.want)
		}
	}
	if d := platform().KillSwitchReapply; d != 0 {
		t.Errorf("outside the lab the platform's period is %v, want the default", d)
	}
}
