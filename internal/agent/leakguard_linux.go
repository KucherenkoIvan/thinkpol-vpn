//go:build linux && !android

package agent

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newHostGuard is the host's IPv6 leak guard (nftables).
func newHostGuard() routetable.Guard { return firewall.NewIPv6Guard() }
