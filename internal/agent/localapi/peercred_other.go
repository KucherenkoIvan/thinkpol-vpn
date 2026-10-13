//go:build !linux && !darwin

package localapi

import (
	"fmt"
	"runtime"
	"syscall"
)

// callerOf refuses: no peer credentials here, so no caller is let in.
func callerOf(syscall.Conn) (Caller, error) {
	return Caller{}, errNoPeerCredentials
}

// A variable, not built in callerOf, so that staticcheck can't prove
// callerOf always fails here and flag the caller's error check.
var errNoPeerCredentials = fmt.Errorf("no peer credentials on %s", runtime.GOOS)
