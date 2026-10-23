// Package plans holds one device-test plan per ticket (lab/devicetest/plan).
// Each records; none judges. A ticket's plan is never bigger than the
// ticket's own change (ORCHESTRATION.md "Device testing").
package plans

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
)

func init() { plan.Register(selftest) }

// selftest is the self-test alone: the captures checked, nothing changed.
var selftest = plan.Plan{
	Ticket:   "selftest",
	Title:    "the self-test alone: the capture on the physical interface checked, nothing changed",
	Budget:   2 * time.Minute,
	Captures: []plan.Capture{{Iface: plan.Physical}},
}
