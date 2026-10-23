//go:build (!linux && !darwin) || android

package main

import (
	"context"
	"runtime"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// newGuard: no leak guard here yet, the route table enforces routes only.
// Windows is TP-047/TP-048's.
func newGuard() routetable.Guard { return nil }

// inspectGuard: no leak guard here to read.
func inspectGuard(context.Context) routetable.GuardReport {
	return routetable.GuardReport{Unreadable: "no leak guard on " + runtime.GOOS}
}
