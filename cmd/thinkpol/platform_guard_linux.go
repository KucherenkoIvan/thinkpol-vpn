//go:build linux && !android

package main

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newGuard is the host's IPv6 leak guard (nftables).
func newGuard() routetable.Guard { return firewall.NewIPv6Guard() }
