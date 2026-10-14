//go:build !linux || android

package agent

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"

// newHostGuard: no leak guard here yet, the route table enforces routes
// only.
//
// TODO(TP-021, macOS round 2): firewall's pf guard once TP-019's data
// plane is merged (see TP-021's Notes). Windows is TP-047/TP-048's.
func newHostGuard() routetable.Guard { return nil }
