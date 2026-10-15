package censor

import "testing"

// TestParseQueueStats reads the kernel's columns, laid out as
// nfnetlink_queue prints them: copy mode 2 and a 65535-byte copy range must
// not read as drops.
func TestParseQueueStats(t *testing.T) {
	proc := "  101   4242     0 2 65535     0     0        3  1\n" +
		"  100   4243     1 2 65535     7     9      120  1\n"
	got, err := ParseQueueStats(proc, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := (QueueStats{Waiting: 1, QueueDropped: 7, UserDropped: 9}); got != want {
		t.Errorf("queue 100: %+v, want %+v", got, want)
	}
	got, err = ParseQueueStats(proc, 101)
	if err != nil {
		t.Fatal(err)
	}
	if got != (QueueStats{}) {
		t.Errorf("queue 101 dropped nothing, got %+v", got)
	}
	if _, err := ParseQueueStats(proc, 102); err == nil {
		t.Error("a queue that isn't there parsed")
	}
}
