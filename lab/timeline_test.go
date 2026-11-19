package lab

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTimelineNotesSlotWait: with THINKPOL_LAB_TIMELINE set, a lab start's
// wait for its slot lands in the file, one line per start; unset, nothing
// is written.
func TestTimelineNotesSlotWait(t *testing.T) {
	file := filepath.Join(t.TempDir(), "timeline")
	from := time.Date(2026, 11, 19, 8, 30, 0, 0, time.UTC)

	t.Setenv(TimelineEnv, "")
	noteSlotWait("tplab-x-t-a", from, from.Add(time.Second))
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("timeline written with %s unset: %v", TimelineEnv, err)
	}

	t.Setenv(TimelineEnv, file)
	noteSlotWait("tplab-x-t-a", from, from.Add(2*time.Minute+1500*time.Millisecond))
	noteSlotWait("tplab-x-t-b", from, from)
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := "08:30:00.000 slot-wait 2m1.5s tplab-x-t-a\n08:30:00.000 slot-wait 0s tplab-x-t-b\n"
	if string(got) != want {
		t.Errorf("timeline:\n%s\nwant:\n%s", got, want)
	}
}
