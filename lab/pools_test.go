//go:build lab

package lab_test

import "github.com/KucherenkoIvan/thinkpol-vpn/lab"

// The lab tests' pools (lab.Pool): a test that takes its lab from one
// gets a lab another test used before it, reset and checked, instead of
// starting one; a test that needs a fresh lab (it checks the lab's start,
// or drives systemd) or is the only one of its topology calls lab.Start.
// A pool's size bounds the labs of its topology at once: tests beyond it
// wait for a lab to come back, which is cheaper than a start as long as
// the tests ahead are short next to a start.
var (
	// The censor tests and the single-tunnel ones.
	tunnelPool = lab.NewPool(lab.Standard().Only(lab.Router, lab.DeviceA, lab.Server1), 3)
	// Two devices, one server: the M0 space and the local API.
	twoDevicePool = lab.NewPool(lab.Standard().Only(lab.Router, lab.DeviceA, lab.DeviceB, lab.Server1), 2)
	// Two devices, one server and the internet: DNS and a second agent.
	internetPool = lab.NewPool(lab.Standard().Only(lab.Router, lab.DeviceA, lab.DeviceB, lab.Server1, lab.Internet), 2)
	// The whole standard lab: two servers, one an exit (egress, blobs),
	// or one with its ingress off.
	standardPool = lab.NewPool(lab.Standard(), 2)
	// The censor matrix's rows and the tests of the camouflage site. Its
	// size is the matrix's labs at once.
	censorPool = lab.NewPool(lab.Upstream().Only(lab.Router, lab.DeviceA, lab.Server1, lab.Camouflage), 5)
)
