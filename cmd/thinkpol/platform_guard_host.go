//go:build (linux && !android) || darwin

package main

import (
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newGuard is the host's IPv6 leak guard (nftables on Linux, a pf anchor
// on macOS).
func newGuard() routetable.Guard { return firewall.NewIPv6Guard() }

// newKillSwitch is the host's kill switch (nftables on Linux, a pf anchor
// on macOS), its direct destinations expiring after direct on Linux (zero:
// firewall.DirectTimeout).
func newKillSwitch(direct time.Duration) func() agent.KillSwitch {
	return func() agent.KillSwitch {
		k := firewall.NewKillSwitch()
		k.SetDirectTimeout(direct)
		return k
	}
}

// inspectGuard reads the host's leak guard as the host holds it.
var inspectGuard = firewall.InspectIPv6Guard

// inspectKillSwitch reads the host's kill switch as the host holds it.
var inspectKillSwitch = firewall.InspectKillSwitch
