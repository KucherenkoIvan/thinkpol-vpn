//go:build linux && !android

package routetable

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"

// newGuard is the IPv6 leak guard of this host's network namespace.
func newGuard() Guard { return firewall.NewIPv6Guard() }

// clearGuard removes what a crashed run's guard left.
func clearGuard() error { return firewall.ClearIPv6Guard() }
