package lab

import (
	"fmt"
	"os"
	"time"
)

// TimelineEnv names a file each lab start appends lines to: how long its
// read of the daemon's subnets took, before the slot; how long it waited
// for its lab slot; when it asked for the subnet allocation lock,
// held it, and ran docker compose up; how long each step from the slot to
// the sealed lab took; and how long its tear-down took. Runs that share
// the file give one timeline of how their labs' start-ups overlap.
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

// noteStart appends a lab's start once it held its slot: the whole of it,
// then each step (create: the subnets and docker compose up, every try;
// inspect: the containers' addresses; bridges: each network's bridge MAC;
// seal: every node sealed), "-" for a step it never reached.
func noteStart(l *Lab, st startTimes, err error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	end := time.Now()
	step := func(from, to time.Time) string {
		if to.IsZero() {
			return "-"
		}
		return to.Sub(from).Round(time.Millisecond).String()
	}
	appendTimeline(path, fmt.Sprintf("%s start %s create %s inspect %s bridges %s seal %s nodes %d networks %d attempts %d %s %s\n",
		timelineStamp(st.slot), end.Sub(st.slot).Round(time.Millisecond),
		step(st.slot, st.created), step(st.created, st.inspected), step(st.inspected, st.bridged), step(st.bridged, st.sealed),
		len(l.Topology.Nodes), len(l.Topology.Networks), l.upAttempt, timelineResult(err), l.Project))
}

// noteSubnetRead appends a lab start's read of the daemon's subnets,
// before it waits for its slot, from..to.
func noteSubnetRead(project string, from, to time.Time, err error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	appendTimeline(path, fmt.Sprintf("%s subnet-read %s %s %s\n", timelineStamp(from), to.Sub(from).Round(time.Millisecond), timelineResult(err), project))
}

// noteDown appends a lab's tear-down, from..to.
func noteDown(project string, from, to time.Time, err error) {
	path := os.Getenv(TimelineEnv)
	if path == "" {
		return
	}
	appendTimeline(path, fmt.Sprintf("%s down %s %s %s\n", timelineStamp(from), to.Sub(from).Round(time.Millisecond), timelineResult(err), project))
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
