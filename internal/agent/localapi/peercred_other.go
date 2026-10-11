//go:build !linux && !darwin

package localapi

import (
	"fmt"
	"runtime"
	"syscall"
)

// callerOf refuses: no peer credentials here, so no caller is let in.
func callerOf(syscall.Conn) (Caller, error) {
	return Caller{}, fmt.Errorf("no peer credentials on %s", runtime.GOOS)
}
