//go:build (!linux && !darwin) || android

package netcfg

import "runtime"

// Inspect has nothing to read where netcfg has no adapter.
func Inspect() Inspection {
	reason := "netcfg has no adapter on " + runtime.GOOS
	return Inspection{RoutesUnreadable: reason, RulesUnreadable: reason}
}
