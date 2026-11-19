package lab

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// TimelineEnv names a file each lab start appends lines to: how long it
// waited for its lab slot (and whether it gave up on the slot queue), and when it asked for the subnet allocation
// lock, held it, and ran docker compose up. Runs
// that share the file give one timeline of how their labs' start-ups
// overlap.
const TimelineEnv = "THINKPOL_LAB_TIMELINE"

func noteTimeline(project string, attempt int, r *reservation, upFrom, upTo time.Time, upErr error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	ms := func(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
	appendTimeline(path, fmt.Sprintf("%s lock-wait %s lock %s-%s (%s) up %s-%s (%s) attempt %d %s %s\n",
		timelineStamp(r.lockWait), ms(r.lockFrom.Sub(r.lockWait)), timelineStamp(r.lockFrom), timelineStamp(r.lockTo), ms(r.lockTo.Sub(r.lockFrom)),
		timelineStamp(upFrom), timelineStamp(upTo), ms(upTo.Sub(upFrom)), attempt, timelineResult(upErr), project))
}

// noteSlotWait appends to the timeline how long a lab's start waited for
// its lab slot, from..to, and whether it got one (err nil).
func noteSlotWait(project string, from, to time.Time, err error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	appendTimeline(path, fmt.Sprintf("%s slot-wait %s %s %s\n", timelineStamp(from), to.Sub(from).Round(time.Millisecond), timelineResult(err), project))
}

// noteSlotUnqueued appends to the timeline that a lab's slot wait gave up
// on the slot queue (reason) and polls the slots in no order.
func noteSlotUnqueued(reason error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	appendTimeline(path, fmt.Sprintf("%s slot-wait unqueued: %s\n", timelineStamp(time.Now()), strings.ReplaceAll(reason.Error(), "\n", " ")))
}

func timelineStamp(t time.Time) string { return t.UTC().Format("15:04:05.000") }

func timelineResult(err error) string {
	if err != nil {
		return "failed"
	}
	return "ok"
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
