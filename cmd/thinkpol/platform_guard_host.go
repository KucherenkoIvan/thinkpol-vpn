//go:build (linux && !android) || darwin

package main

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newGuard is the host's IPv6 leak guard (nftables on Linux, a pf anchor
// on macOS).
func newGuard() routetable.Guard { return firewall.NewIPv6Guard() }

// inspectGuard reads the host's leak guard as the host holds it.
var inspectGuard = firewall.InspectIPv6Guard
