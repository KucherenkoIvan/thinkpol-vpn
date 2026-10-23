// Package plans holds one device-test plan per ticket (lab/devicetest/plan):
// functions returning data, so nothing here runs unless the user side
// asks for a plan. Each records; none judges. A ticket's plan is never
// bigger than the ticket's own change.
package plans

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
)

// All are the plans.
func All() []plan.Plan { return []plan.Plan{selfTest(), tp096()} }

// selfTest is the self-test alone: the capture checked, no change of a
// plan's (the self-test's own harmless change goes through the journal and
// back).
func selfTest() plan.Plan {
	return plan.Plan{
		Ticket:  "selftest",
		Title:   "the self-test alone: the capture on the physical interface checked, no change of a plan's",
		Budget:  2 * time.Minute,
		Capture: plan.Capture{Iface: plan.Physical},
	}
}
