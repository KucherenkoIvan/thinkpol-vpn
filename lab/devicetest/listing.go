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
		for _, p := range allPlans() {
			fmt.Printf("%-9s %s\n", p.Ticket, p.Title)
		}
		return nil
	}
	p, ok := plan.Lookup(allPlans(), args[0])
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
	w("budget %v: past it the dead-man restores the Mac", p.Budget)
	w("first, the self-test (%v, before any change): one harmless change through the journal and back,", selfTestBudget)
	w("  then the capture must see a marker, miss one its filter excludes, and decode with tcpdump -n -A -r")
	if c := p.Capture; c.Iface != "" {
		iface := c.Iface
		if iface == plan.Physical {
			iface = "the physical interface (" + phys + ")"
		}
		w("capture: %s, filter %q, running until the run ends; its pcap is kept in the evidence", iface, controlFilter(c.Filter, "N"))
		w("  (the plan's filter %q with the self-test's controls: N is the negative marker's source port)", c.Filter)
	}
	for i, st := range p.Steps {
		w("step %d %s", i+1, st.Name)
		for _, op := range st.Ops {
			w("  %s", describeOp(op))
			if op.Kind == plan.OpDo {
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
	case plan.OpRead:
		return "root read: " + strings.Join(op.Argv, " ")
	case plan.OpDo:
		does, _, err := describeChange(op.Change)
		if err != nil {
			return fmt.Sprintf("change:    %s, refused: %v", op.Change.Kind, err)
		}
		return "change:    " + does
	case plan.OpUndoLast:
		return "undo now:  the plan's newest change"
	}
	return fmt.Sprintf("operation %d", op.Kind)
}

func undoText(c plan.Change) string {
	if _, undo, err := describeChange(c); err == nil {
		return undo
	}
	return "?"
}

func describeChange(c plan.Change) (does, undo string, err error) {
	spec, err := changeSpec(c)
	if err != nil {
		return "", "", err
	}
	return safety.Describe(spec)
}
