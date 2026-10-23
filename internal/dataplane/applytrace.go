package dataplane

import "time"

// Steps only the Apply trace names: neither fails an Apply.
const (
	// StepRules is compiling the routing rules (an unavailable preset is
	// in Status, failing closed).
	StepRules Step = "rules"
	// StepRouteTableShrink is taking out of the OS routing table, first,
	// the direct routes the new rules don't keep (a failure falls back to
	// nothing direct).
	StepRouteTableShrink Step = "route_table_shrink"
)

// ApplyTrace is the last Apply, for diagnostics: when it started, how
// long it took, the step it failed at (as Status.LastApplyError), and
// its steps in the order they ran. A step's time runs from the end of the
// one before it.
type ApplyTrace struct {
	Started time.Time
	Took    time.Duration
	Failed  Step
	Steps   []ApplyStep
}

// ApplyStep is one step of an Apply.
type ApplyStep struct {
	Step   Step
	Took   time.Duration
	Failed bool
}

// applyTrace records the Apply in progress; only the goroutine running
// it touches it.
type applyTrace struct {
	ApplyTrace
	last time.Time
}

func newApplyTrace(now time.Time) *applyTrace {
	return &applyTrace{ApplyTrace: ApplyTrace{Started: now}, last: now}
}

// mark ends step, failed if err isn't nil. A nil trace (no Apply in
// progress) records nothing.
func (t *applyTrace) mark(step Step, err error) {
	if t == nil {
		return
	}
	now := time.Now()
	t.Steps = append(t.Steps, ApplyStep{Step: step, Took: now.Sub(t.last), Failed: err != nil})
	t.last = now
}

// done is the trace of an Apply that failed at failed ("": it didn't).
func (t *applyTrace) done(failed Step) ApplyTrace {
	tr := t.ApplyTrace
	tr.Took, tr.Failed = time.Since(t.Started), failed
	return tr
}
