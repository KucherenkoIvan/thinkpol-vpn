//go:build !linux || android

package dns

import (
	"fmt"
	"runtime"
	"syscall"
)

// BindToInterface binds sockets to an interface where the platform can;
// here sockets fail rather than leave unbound.
func BindToInterface(name string) func(network, address string, c syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return fmt.Errorf("dns: binding sockets to %s: not on %s yet", name, runtime.GOOS)
	}
}
