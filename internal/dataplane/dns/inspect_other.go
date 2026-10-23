//go:build (!linux && !darwin) || android

package dns

import (
	"context"
	"runtime"
)

// Inspect has no resolvers to read here yet.
func Inspect(context.Context) HostReport {
	return HostReport{Sources: []HostSource{{Name: runtime.GOOS, Unreadable: "the resolvers aren't read on " + runtime.GOOS}}}
}
