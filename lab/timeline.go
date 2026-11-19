package lab

import (
	"fmt"
	"os"
	"time"
)

// TimelineEnv names a file each lab start appends lines to: how long it
// waited for its lab slot, and when it asked for the subnet allocation
// lock, held it, and ran docker compose up. Runs
// that share the file give one timeline of how their labs' start-ups
// overlap.
const TimelineEnv = "THINKPOL_LAB_TIMELINE"

func noteTimeline(project string, attempt int, r *reservation, upFrom, upTo time.Time, upErr error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	stamp := func(t time.Time) string { return t.UTC().Format("15:04:05.000") }
	result := "ok"
	if upErr != nil {
		result = "failed"
	}
	ms := func(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
	appendTimeline(path, fmt.Sprintf("%s lock-wait %s lock %s-%s (%s) up %s-%s (%s) attempt %d %s %s\n",
		stamp(r.lockWait), ms(r.lockFrom.Sub(r.lockWait)), stamp(r.lockFrom), stamp(r.lockTo), ms(r.lockTo.Sub(r.lockFrom)),
		stamp(upFrom), stamp(upTo), ms(upTo.Sub(upFrom)), attempt, result, project))
}

// noteSlotWait appends to the timeline how long a lab's start waited for
// its lab slot, from..to.
func noteSlotWait(project string, from, to time.Time) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	appendTimeline(path, fmt.Sprintf("%s slot-wait %s %s\n", from.UTC().Format("15:04:05.000"), to.Sub(from).Round(time.Millisecond), project))
}

func appendTimeline(path, line string) {
	// One write of a short line to an O_APPEND file: lines from concurrent
	// runs don't interleave.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}
