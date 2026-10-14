//go:build !linux || android

package agent

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"

// newHostGuard: no leak guard here yet, the route table enforces routes
// only.
//
// TODO(TP-078): macOS's pf guard. Windows is TP-047/TP-048's.
func newHostGuard() routetable.Guard { return nil }
