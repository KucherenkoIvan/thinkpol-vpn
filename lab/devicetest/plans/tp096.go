package plans

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
)

func init() { plan.Register(tp096) }

// tp096 records TP-096's pfctl listings (the bypass check's, TP-126) on a
// stock Mac, then pf's answer to a skip on a name no interface has (`set
// skip on lo`, prepended to the stock rules so Apple's hook stays), and
// the stock rules back. Needs no native IPv6 and no exit server: the
// listings with the guard applied, and what health says, wait for the
// exit driver.
var tp096 = plan.Plan{
	Ticket:   "TP-096",
	Title:    "pfctl listings on a stock Mac, and a skip on a name no interface has",
	Budget:   5 * time.Minute,
	Captures: []plan.Capture{{Iface: plan.Physical, Filter: "ip6"}},
	Steps: []plan.Step{
		{Name: "stock", Ops: listings()},
		{Name: "skip-on-lo", Ops: append(append([]plan.Op{
			plan.Make(plan.PfMain("set skip on lo")),
		}, listings()...),
			plan.Root("pfctl", "-s", "rules"),
			plan.UndoLast(),
			plan.Root("pfctl", "-s", "Interfaces", "-v"),
			plan.Root("pfctl", "-s", "rules"),
		)},
	},
}

// listings are what the guard's bypass check reads.
func listings() []plan.Op {
	return []plan.Op{
		plan.Root("pfctl", "-s", "Interfaces", "-v"),
		plan.Root("pfctl", "-a", "com.apple", "-s", "Anchors"),
		plan.Root("pfctl", "-s", "References"),
	}
}
