//go:build !unix

package localapi

import (
	"fmt"
	"net"
	"runtime"
)

// Listen refuses: the local API on Windows is a named pipe (TP-047).
func Listen(string, Policy) (net.Listener, error) {
	return nil, fmt.Errorf("no local API socket on %s yet", runtime.GOOS)
}
