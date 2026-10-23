// Package plan is what a device-test plan is written in: data, not code.
// A plan lists its steps, and each step its operations: a root read (a
// listing the core allows), a change (an action of the core's, named by
// kind), or undoing the newest change now. The runner (lab/devicetest)
// does exactly what the plan lists and nothing else; a plan can't run a
// command or reach the core itself (depguard), so its listing is
// everything a run may do. A plan records and never judges: what a run
// saw is judged afterwards, from the evidence.
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
	// Captures run from the self-test to the end of the run.
	Captures []Capture
	// NeedsExit says the run needs the exit server (and so the private
	// config file that names it).
	NeedsExit bool
	Steps     []Step
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

// OpKind is what an operation does.
type OpKind int

const (
	// RootRead runs a listing as root and saves its output.
	RootRead OpKind = iota + 1
	// Do makes a change: an action of the core's, journaled with its undo.
	Do
	// UndoNewest undoes the newest change now, not only at the end.
	UndoNewest
)

// Op is one operation.
type Op struct {
	Kind   OpKind
	Argv   []string
	Change Change
}

// Change names an action of the core's by kind, with its parameters.
type Change struct {
	Kind   string
	Params map[string]string
}

// Root is a root read of argv (a bare command name first).
func Root(argv ...string) Op { return Op{Kind: RootRead, Argv: argv} }

// Make is a change.
func Make(c Change) Op { return Op{Kind: Do, Change: c} }

// UndoLast undoes the newest change now.
func UndoLast() Op { return Op{Kind: UndoNewest} }

// PfMain loads pf's main ruleset as one line, then the stock rules
// (/etc/pf.conf). Its undo loads the stock rules.
func PfMain(prepend string) Change {
	return Change{Kind: "pf-main", Params: map[string]string{"prepend": prepend}}
}

var (
	ticketID = regexp.MustCompile(`^(TP-[0-9]+|selftest)$`)
	stepName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// Validate checks the plan's shape; what a change or read may be is the
// core's to check.
func (p Plan) Validate() error {
	if !ticketID.MatchString(p.Ticket) {
		return fmt.Errorf("plan %q: ticket id", p.Ticket)
	}
	if p.Budget <= 0 || p.Budget > time.Hour {
		return fmt.Errorf("plan %s: budget %v (up to an hour)", p.Ticket, p.Budget)
	}
	seen := map[string]bool{}
	for _, s := range p.Steps {
		if !stepName.MatchString(s.Name) || seen[s.Name] {
			return fmt.Errorf("plan %s: step name %q", p.Ticket, s.Name)
		}
		seen[s.Name] = true
		for _, op := range s.Ops {
			if err := op.validate(); err != nil {
				return fmt.Errorf("plan %s, step %s: %w", p.Ticket, s.Name, err)
			}
		}
	}
	return nil
}

func (op Op) validate() error {
	switch op.Kind {
	case RootRead:
		if len(op.Argv) == 0 {
			return fmt.Errorf("an empty root read")
		}
	case Do:
		if op.Change.Kind == "" {
			return fmt.Errorf("a change without a kind")
		}
	case UndoNewest:
	default:
		return fmt.Errorf("operation kind %d", op.Kind)
	}
	return nil
}

var registry = map[string]Plan{}

// Register adds a plan; an invalid or second plan for a ticket panics.
func Register(p Plan) {
	if err := p.Validate(); err != nil {
		panic(err)
	}
	if _, dup := registry[p.Ticket]; dup {
		panic("plan: a second plan for " + p.Ticket)
	}
	registry[p.Ticket] = p
}

// Lookup is the plan for ticket (any case).
func Lookup(ticket string) (Plan, bool) {
	t := strings.ToUpper(ticket)
	if strings.EqualFold(ticket, "selftest") {
		t = "selftest"
	}
	p, ok := registry[t]
	return p, ok
}

// All are the plans, by ticket.
func All() []Plan {
	var out []Plan
	for _, p := range registry {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Plan) int { return strings.Compare(a.Ticket, b.Ticket) })
	return out
}
