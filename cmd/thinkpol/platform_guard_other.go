//go:build (!linux && !darwin) || android

package main

import (
	"context"
	"runtime"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newKillSwitch: no kill switch here yet (Windows: TP-076).
func newKillSwitch() agent.KillSwitch { return nil }

// newGuard: no leak guard here yet, the route table enforces routes only.
// Windows is TP-047/TP-048's.
func newGuard() routetable.Guard { return nil }

// inspectGuard: no leak guard here to read.
func inspectGuard(context.Context) routetable.GuardReport {
	return routetable.GuardReport{Unreadable: "no leak guard on " + runtime.GOOS}
}

// inspectKillSwitch: no kill switch here to read.
func inspectKillSwitch(context.Context) firewall.KillSwitchReport {
	return firewall.KillSwitchReport{Unreadable: "no kill switch on " + runtime.GOOS}
}
