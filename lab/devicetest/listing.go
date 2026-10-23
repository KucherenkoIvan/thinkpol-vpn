//go:build darwin || linux

package main

import (
	"fmt"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

func cmdPlans(args []string) error {
	if len(args) == 0 {
		for _, p := range plan.All() {
			fmt.Printf("%-9s %s\n", p.Ticket, p.Title)
		}
		return nil
	}
	p, ok := plan.Lookup(args[0])
	if !ok {
		return fmt.Errorf("no plan for %s", args[0])
	}
	phys, err := physicalInterface()
	if err != nil {
		phys = "?"
	}
	fmt.Print(listing(p, phys))
	return nil
}

// listing is everything a run of p may do, in order: the owner reads it
// before typing yes, and it is the run's plan.txt.
func listing(p plan.Plan, phys string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("%s: %s", p.Ticket, p.Title)
	exit := "not needed"
	if p.NeedsExit {
		exit = "needed (the private config file names it)"
	}
	w("budget %v: past it the dead-man restores the Mac; exit server: %s", p.Budget, exit)
	w("first, the self-test (%v, before any change): one harmless change through the journal and back,", selfTestBudget)
	w("  then each capture must see a marker, miss one its filter excludes, and decode with tcpdump -n -A -r")
	for _, c := range p.Captures {
		iface := c.Iface
		if iface == plan.Physical {
			iface = "the physical interface (" + phys + ")"
		}
		w("capture: %s, filter %q, kept in the evidence until the run ends", iface, c.Filter)
	}
	for i, st := range p.Steps {
		w("step %d %s", i+1, st.Name)
		for _, op := range st.Ops {
			w("  %s", describeOp(op))
			if op.Kind == plan.Do {
				w("    undo: %s", undoText(op.Change))
			}
		}
	}
	w("then, and on Ctrl-C, a closed terminal or a crash: every change undone, newest first,")
	w("  and the Mac compared with its baseline (CLEAN, LEFT with what to do, or REBOOT)")
	return b.String()
}

func describeOp(op plan.Op) string {
	switch op.Kind {
	case plan.RootRead:
		return "root read: " + strings.Join(op.Argv, " ")
	case plan.Do:
		if a, err := changeAction(op.Change); err == nil {
			return "change:    " + a.Does()
		}
		return "change:    " + op.Change.Kind + " (this OS has no such action)"
	case plan.UndoNewest:
		return "undo now:  the newest change"
	}
	return fmt.Sprintf("operation %d", op.Kind)
}

func undoText(c plan.Change) string {
	if a, err := changeAction(c); err == nil {
		return a.UndoText()
	}
	return "?"
}

func changeAction(c plan.Change) (safety.Action, error) {
	spec, err := changeSpec(c)
	if err != nil {
		return nil, err
	}
	return safety.Decode(spec)
}
