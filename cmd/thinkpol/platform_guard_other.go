//go:build (!linux && !darwin) || android

package main

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"

// newGuard: no leak guard here yet, the route table enforces routes only.
// Windows is TP-047/TP-048's.
func newGuard() routetable.Guard { return nil }
