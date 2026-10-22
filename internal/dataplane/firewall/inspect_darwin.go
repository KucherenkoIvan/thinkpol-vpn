package firewall

import (
	"context"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// InspectIPv6Guard reads the guard's anchor and pf's state as pfctl lists
// them, for diagnostics; it changes nothing.
func InspectIPv6Guard(context.Context) routetable.GuardReport {
	return routetable.GuardReport{Where: "pf anchor " + GuardAnchor, Unreadable: "not read on macOS yet"}
}
