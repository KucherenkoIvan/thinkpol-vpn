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

// TestWaitForSlotTimesTheWait: a start whose clock asks for it gets how
// long it waited for its slot, both when it got one after another start
// let go of it and when it ran out of time.
func TestWaitForSlotTimesTheWait(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv(MaxLabsEnv, "1")
	ctx := context.Background()
	budget := startBudget{before: time.Minute, wait: time.Minute, start: time.Minute}
	held, err := waitForSlot(ctx, budget.begin(time.Time{}), "tplab-x-t-a", "")
	if err != nil {
		t.Fatal(err)
	}
	const hold = 300 * time.Millisecond
	go func() {
		time.Sleep(hold)
		held()
	}()
	var waited time.Duration
	clock := budget.begin(time.Time{})
	clock.slotWait = &waited
	release, err := waitForSlot(ctx, clock, "tplab-x-t-b", "")
	if err != nil {
		t.Fatal(err)
	}
	if waited < hold || waited > time.Minute {
		t.Errorf("waited %v for a slot held %v", waited, hold)
	}

	budget.wait = 200 * time.Millisecond
	waited = 0
	clock = budget.begin(time.Time{})
	clock.slotWait = &waited
	if _, err := waitForSlot(ctx, clock, "tplab-x-t-c", ""); err == nil {
		t.Fatal("got the slot that is held")
	}
	release()
	if waited < budget.wait {
		t.Errorf("a wait that ran out after %v noted as %v", budget.wait, waited)
	}
}
