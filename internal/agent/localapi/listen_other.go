//go:build !unix

package localapi

import (
	"fmt"
	"net"
	"runtime"
)

// Listen refuses: the local API on Windows is a named pipe (TP-047).
func Listen(string, Policy) (net.Listener, error) {
	return nil, errNoSocket
}

// A variable, not built in Listen, so that staticcheck can't prove Listen
// always fails here and flag the callers' error checks.
var errNoSocket = fmt.Errorf("no local API socket on %s yet", runtime.GOOS)
