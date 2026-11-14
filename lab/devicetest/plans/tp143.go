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
// in otherwise. No capture: nothing here is on the wire. On a Mac whose
// pfctl marks no skip, the core can't show a skip gone: the lo undo fails
// and the run stops to ask, `continue` goes on to lo0, the run ends LEFT,
// and a reboot, then `devicetest restore`, closes it.
func tp143() plan.Plan {
	listings := []plan.Op{
		plan.Read("pfctl", "-s", "Interfaces", "-v"),
		plan.Read("pfctl", "-s", "Interfaces", "-vv"),
		plan.Read("pfctl", "-s", "info", "-v"),
	}
	skip := func(iface string) []plan.Op {
		ops := append([]plan.Op{plan.Do(plan.PfSkip(iface))}, listings...)
		return append(ops, plan.UndoLast(), plan.Read("pfctl", "-s", "Interfaces", "-v"))
	}
	return plan.Plan{
		Ticket: "TP-143",
		Title:  "does pf mark a skipped interface: pf's listings on a stock Mac, with a skip on lo, then on lo0, each undone",
		Budget: 5 * time.Minute,
		Steps:  []plan.Step{{Name: "stock", Ops: listings}, {Name: "skip-on-lo", Ops: skip("lo")}, {Name: "skip-on-lo0", Ops: skip("lo0")}},
	}
}
