//go:build !linux && !darwin

package localapi

import (
	"fmt"
	"net"
	"runtime"
)

// callerOf refuses: no peer credentials here, so no caller is let in.
func callerOf(*net.UnixConn) (Caller, error) {
	return Caller{}, fmt.Errorf("no peer credentials on %s", runtime.GOOS)
}
