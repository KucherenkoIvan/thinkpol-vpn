// Package plan is what a device-test plan is written in: data, not code.
// A plan lists its steps, and each step its operations: a root read (a
// listing the core allows), a change (one of the core's kinds), or undoing
// the newest change now. The runner (lab/devicetest) does exactly what
// the plan lists and nothing else; a plan can't run a command or reach
// the core (depguard), so its listing is everything a run may do. A plan
// records and never judges: what a run saw is judged afterwards, from
// the evidence.
package plan

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Plan is one ticket's device run.
type Plan struct {
	// Ticket is the ticket's id (TP-NNN), or "selftest".
	Ticket string
	Title  string
	// Budget is the run's deadline: past it the dead-man restores the
	// host unless a restore is making progress.
	Budget time.Duration
	// Capture runs from the self-test to the end of the run; an empty
	// Iface is none. One a plan: the self-test checks it in 10 s.
	Capture Capture
	Steps   []Step
}

// Capture is a capture on one interface, with a tcpdump filter ("" for
// everything).
type Capture struct {
	Iface  string
	Filter string
}

// Physical is the interface of the IPv4 default route, as an Iface.
const Physical = "physical"

// Step is a named group of operations; the evidence has a folder per step.
type Step struct {
	Name string
	Ops  []Op
}

// OpKind is what an operation does; the names are the helper's.
type OpKind int

const (
	// OpRead runs a listing as root and saves its output.
	OpRead OpKind = iota + 1
	// OpDo makes a change, journaled with its undo.
	OpDo
	// OpUndoLast undoes the plan's newest change now, not only at the end.
	OpUndoLast
)

// Op is one operation.
type Op struct {
	Kind   OpKind
	Argv   []string
	Change Change
}

// Change names one of the core's kinds of change, with its parameters.
type Change struct {
	Kind   string
	Params map[string]string
}

// Read is a root read of argv (a bare command name first).
func Read(argv ...string) Op { return Op{Kind: OpRead, Argv: argv} }

// Do makes a change.
func Do(c Change) Op { return Op{Kind: OpDo, Change: c} }

// UndoLast undoes the plan's newest change now.
func UndoLast() Op { return Op{Kind: OpUndoLast} }

// PfSkip loads `set skip on iface` before the stock pf rules
// (/etc/pf.conf); its undo loads the stock rules.
func PfSkip(iface string) Change {
	return Change{Kind: "pf-skip", Params: map[string]string{"iface": iface}}
}

var (
	ticketID = regexp.MustCompile(`^(TP-[0-9]+|selftest)$`)
	stepName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// Validate checks the plan's shape; what a change or read may be is the
// core's to check. An undo needs a change of the plan's own still made
// before it: it would undo the run's capture otherwise.
func (p Plan) Validate() error {
	if !ticketID.MatchString(p.Ticket) {
		return fmt.Errorf("plan %q: ticket id", p.Ticket)
	}
	if p.Budget <= 0 || p.Budget > time.Hour {
		return fmt.Errorf("plan %s: budget %v (up to an hour)", p.Ticket, p.Budget)
	}
	seen, made := map[string]bool{}, 0
	for _, s := range p.Steps {
		if !stepName.MatchString(s.Name) || seen[s.Name] {
			return fmt.Errorf("plan %s: step name %q", p.Ticket, s.Name)
		}
		seen[s.Name] = true
		for _, op := range s.Ops {
			switch {
			case op.Kind == OpRead && len(op.Argv) == 0:
				return fmt.Errorf("plan %s, step %s: an empty root read", p.Ticket, s.Name)
			case op.Kind == OpDo && op.Change.Kind == "":
				return fmt.Errorf("plan %s, step %s: a change without a kind", p.Ticket, s.Name)
			case op.Kind == OpDo:
				made++
			case op.Kind == OpUndoLast && made == 0:
				return fmt.Errorf("plan %s, step %s: an undo with no change of the plan's before it", p.Ticket, s.Name)
			case op.Kind == OpUndoLast:
				made--
			case op.Kind != OpRead:
				return fmt.Errorf("plan %s, step %s: operation kind %d", p.Ticket, s.Name, op.Kind)
			}
		}
	}
	return nil
}

// Lookup is the plan for ticket (any case) among plans.
func Lookup(plans []Plan, ticket string) (Plan, bool) {
	i := slices.IndexFunc(plans, func(p Plan) bool { return strings.EqualFold(p.Ticket, ticket) })
	if i < 0 {
		return Plan{}, false
	}
	return plans[i], true
}
