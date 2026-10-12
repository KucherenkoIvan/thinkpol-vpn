//go:build linux && !android

package dns

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// BindToInterface is a socket Control that binds sockets to the named
// interface (SO_BINDTODEVICE): what they send leaves through it or not at
// all, whatever the routes say.
func BindToInterface(name string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if cerr := c.Control(func(fd uintptr) {
			err = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
		}); cerr != nil {
			return cerr
		}
		return err
	}
}
