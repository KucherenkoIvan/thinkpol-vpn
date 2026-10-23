package plans

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
)

// tp096 records TP-096's pfctl listings (the guard's bypass check's) on a
// stock Mac, then pf's answer to a skip on a name no interface has (`set
// skip on lo` before the stock rules, so Apple's hook stays), and the
// stock rules back. Needs no native IPv6 and no exit server; the listings
// with the guard applied, and what health says, need a connected agent.
func tp096() plan.Plan {
	listings := []plan.Op{
		plan.Read("pfctl", "-s", "Interfaces", "-v"),
		plan.Read("pfctl", "-a", "com.apple", "-s", "Anchors"),
		plan.Read("pfctl", "-s", "References"),
	}
	skip := append(append([]plan.Op{plan.Do(plan.PfSkip("lo"))}, listings...),
		plan.Read("pfctl", "-s", "rules"),
		plan.UndoLast(),
		plan.Read("pfctl", "-s", "Interfaces", "-v"),
		plan.Read("pfctl", "-s", "rules"),
	)
	return plan.Plan{
		Ticket:  "TP-096",
		Title:   "pfctl listings on a stock Mac, and a skip on a name no interface has",
		Budget:  5 * time.Minute,
		Capture: plan.Capture{Iface: plan.Physical, Filter: "ip6"},
		Steps:   []plan.Step{{Name: "stock", Ops: listings}, {Name: "skip-on-lo", Ops: skip}},
	}
}
