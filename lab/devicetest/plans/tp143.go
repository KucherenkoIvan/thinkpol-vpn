package plans

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
)

// tp143 records whether pf marks a skipped interface at all: pf's
// listings on a stock Mac, then with `set skip on lo` (the group name)
// and with `set skip on lo0` (the interface) loaded before the stock
// rules, each undone before the next. Beside `-s Interfaces -v`, which
// marked nothing in TP-096's run, it keeps the listings a skip could show
// in otherwise. No capture: nothing here is on the wire.
//
// When lo's undo fails, the run stops to ask, and the prompt says what to
// type for each case. pf never listed the skip ("pf listed no skipped
// interface"): the core can't show it gone, `continue` goes on to lo0,
// whose load is allowed (pf skips what it did at the baseline, as far as
// it shows), the run ends LEFT, and a reboot, then `devicetest restore`,
// closes it. pf listed the skip and it survived the reload ("pf still
// lists this run's skip", REBOOT): lo0's load is refused (pf's skips
// differ from the baseline), so Enter, which restores and ends the run,
// is the answer; after `continue`, steps/03-skip-on-lo0/ would hold lo's
// listings and lo's retried undo, which its NOTE.txt says.
func tp143() plan.Plan {
	listings := []plan.Op{
		plan.Read("pfctl", "-s", "Interfaces", "-v"),
		plan.Read("pfctl", "-s", "Interfaces", "-vv"),
		plan.Read("pfctl", "-s", "info", "-v"),
	}
	skip := func(iface, doFailed, undoFailed string) []plan.Op {
		ops := append([]plan.Op{plan.IfFailed(plan.Do(plan.PfSkip(iface)), doFailed)}, listings...)
		return append(ops, plan.IfFailed(plan.UndoLast(), undoFailed), plan.Read("pfctl", "-s", "Interfaces", "-v"))
	}
	return plan.Plan{
		Ticket: "TP-143",
		Title:  "does pf mark a skipped interface: pf's listings on a stock Mac, with a skip on lo, then on lo0, each undone",
		Budget: 5 * time.Minute,
		Steps: []plan.Step{
			{Name: "stock", Ops: listings},
			{Name: "skip-on-lo", Ops: skip("lo",
				"lo's load failed: press Enter.",
				`If the error says "pf listed no skipped interface", type continue (lo0's step runs next). `+
					`If it says "pf still lists this run's skip", press Enter: lo0's load would be refused. Anything else: press Enter.`)},
			{Name: "skip-on-lo0", Ops: skip("lo0",
				"lo0's load was refused or failed (lo's skip still listed, if lo's undo said so): press Enter. "+
					"continue would record this step without lo0's skip and retry lo's undo (its NOTE.txt says so).",
				`If this step's load was refused, this undo was lo's again: press Enter. `+
					`If the error says "pf listed no skipped interface", press Enter: the run ends LEFT; reboot, then devicetest restore. Anything else: press Enter.`)},
		},
	}
}
