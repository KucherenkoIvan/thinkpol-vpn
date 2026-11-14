package plans

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
)

// tp085 captures the physical interface, unfiltered, while the owner
// connects over reality (TP-029: the TLS hello to the exit), looks up one
// direct and one tunnel-bound name (TP-085: which queries show on the
// wire), browses, and disconnects. It runs with the kill switch OFF: on,
// it likely refuses the self-test's marker, and the core's restore knows
// nothing of its pf reference or anchor. The baseline is taken
// disconnected, so the run disconnects before its restore compares pf.
// Nothing here names the exit: the owner's notes and the capture say
// which server and names were used. Under the presets every name goes
// through the tunnel (GeoIP never decides a name), so the direct name
// needs a domain or domain-suffix rule that says direct.
func tp085() plan.Plan {
	ask := func(name, text string, ops ...plan.Op) plan.Step {
		return plan.Step{Name: name, Ops: append([]plan.Op{plan.Ask(text)}, ops...)}
	}
	return plan.Plan{
		Ticket:  "TP-085",
		Title:   "the physical interface captured, unfiltered, through a reality connect, a direct and a tunnel-bound name, a browse; kill switch off",
		Budget:  15 * time.Minute,
		Capture: plan.Capture{Iface: plan.Physical},
		Steps: []plan.Step{
			ask("connect", "With the kill switch off, connect over reality; wait until thinkpol status says connected.",
				plan.Read("scutil", "--dns"), plan.Read("netstat", "-rn")),
			ask("direct-name", "Look up a short name, new this run, that a domain or domain-suffix rule sends direct; the note is that name."),
			ask("tunnel-name", "Look up a short name, new this run, under example.net (no rule sends it direct); the note is that name."),
			ask("browse", "Browse one light page (no video) for about 30 s; the note is which."),
			ask("disconnect", "Disconnect; wait until thinkpol status says disconnected."),
		},
	}
}
