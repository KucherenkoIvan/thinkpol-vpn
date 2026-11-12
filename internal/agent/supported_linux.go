//go:build linux && !android

package agent

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"

// supported reports whether this OS can run a node's data plane in mode.
func supported(Mode) error { return nil }

// killSwitchPlace is where the host holds the kill switch, as a report
// names it.
const killSwitchPlace = "the nftables table inet " + firewall.KillSwitchTable
