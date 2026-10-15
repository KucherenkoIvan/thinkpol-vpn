//go:build (!linux && !darwin) || android

package agent

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"

// newHostGuard: no leak guard here yet, the route table enforces routes
// only. Windows is TP-047/TP-048's.
func newHostGuard() routetable.Guard { return nil }
