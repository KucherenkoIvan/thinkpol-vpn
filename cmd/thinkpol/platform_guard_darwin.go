package main

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newGuard is the host's IPv6 leak guard (a pf anchor).
func newGuard() routetable.Guard { return firewall.NewIPv6Guard() }
