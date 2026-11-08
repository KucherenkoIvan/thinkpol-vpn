//go:build (linux && !android) || darwin

package main

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newGuard is the host's IPv6 leak guard (nftables on Linux, a pf anchor
// on macOS).
func newGuard() routetable.Guard { return firewall.NewIPv6Guard() }

// newKillSwitch is the host's kill switch (nftables on Linux, a pf anchor
// on macOS).
func newKillSwitch() agent.KillSwitch { return firewall.NewKillSwitch() }

// inspectGuard reads the host's leak guard as the host holds it.
var inspectGuard = firewall.InspectIPv6Guard
