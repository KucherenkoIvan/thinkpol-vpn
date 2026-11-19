package lab

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestTimelineNotesSlotWait: with THINKPOL_LAB_TIMELINE set, every lab
// start's wait for its slot lands in the file, one line per start, the
// one that got a slot and the one that ran out of time alike. The slots are
// this test's own: a lock directory under its TMPDIR, one slot.
func TestTimelineNotesSlotWait(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv(MaxLabsEnv, "1")
	file := filepath.Join(t.TempDir(), "timeline")
	t.Setenv(TimelineEnv, file)
	ctx := context.Background()
	budget := startBudget{before: time.Minute, wait: time.Minute, start: time.Minute}

	release, err := waitForSlot(ctx, budget.begin(time.Time{}), "tplab-x-t-a", "")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	budget.wait = 0 // the one slot is held: no wait gets it
	if _, err := waitForSlot(ctx, budget.begin(time.Time{}), "tplab-x-t-b", ""); err == nil || !strings.Contains(err.Error(), "no lab slot within 0s") {
		t.Fatalf("a second start with the only slot held: %v, want no lab slot within 0s", err)
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile(`^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3} slot-wait [0-9.]+m?s ok tplab-x-t-a\n` +
		`[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3} slot-wait [0-9.]+m?s failed tplab-x-t-b\n$`)
	if !want.Match(got) {
		t.Errorf("timeline:\n%s\nwant a line per start, ok then failed:\n%s", got, want)
	}
}

// TestTimelineSlotWaitLine: a slot wait's line gives its start, its length
// and its outcome.
func TestTimelineSlotWaitLine(t *testing.T) {
	file := filepath.Join(t.TempDir(), "timeline")
	t.Setenv(TimelineEnv, file)
	from := time.Date(2026, 11, 19, 8, 30, 0, 0, time.UTC)
	noteSlotWait("tplab-x-t-a", from, from.Add(2*time.Minute+1500*time.Millisecond), nil)
	noteSlotWait("tplab-x-t-b", from, from, context.DeadlineExceeded)
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := "08:30:00.000 slot-wait 2m1.5s ok tplab-x-t-a\n08:30:00.000 slot-wait 0s failed tplab-x-t-b\n"
	if string(got) != want {
		t.Errorf("timeline:\n%s\nwant:\n%s", got, want)
	}
}

// TestTimelineStartAndDownLines: a start's line gives the whole of it from
// the slot and each step's length, "-" for a step it never reached; a
// tear-down's line its length.
func TestTimelineStartAndDownLines(t *testing.T) {
	file := filepath.Join(t.TempDir(), "timeline")
	t.Setenv(TimelineEnv, file)
	slot := time.Now().Add(-time.Hour)
	l := &Lab{Project: "tplab-x-t-a", Topology: Standard().Only(Router, DeviceA), upAttempt: 2}
	noteStart(l, startTimes{
		slot:      slot,
		created:   slot.Add(40 * time.Second),
		inspected: slot.Add(41500 * time.Millisecond),
		bridged:   slot.Add(43 * time.Second),
		sealed:    slot.Add(45 * time.Second),
	}, nil)
	noteStart(l, startTimes{slot: slot, created: slot.Add(3 * time.Second)}, context.DeadlineExceeded)
	noteDown("tplab-x-t-a", slot, slot.Add(7250*time.Millisecond), nil)
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile(`^[0-9:.]{12} start 1h[0-9ms.]+ create 40s inspect 1.5s bridges 1.5s seal 2s nodes 2 networks 2 attempts 2 ok tplab-x-t-a\n` +
		`[0-9:.]{12} start 1h[0-9ms.]+ create 3s inspect - bridges - seal - nodes 2 networks 2 attempts 2 failed tplab-x-t-a\n` +
		`[0-9:.]{12} down 7.25s ok tplab-x-t-a\n$`)
	if !want.Match(got) {
		t.Errorf("timeline:\n%s\nwant:\n%s", got, want)
	}
}
