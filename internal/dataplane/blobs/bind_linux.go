package blobs

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindTo binds a socket to the interface (SO_BINDTODEVICE): a listener then
// takes only what arrives through it, and a dial can leave only through it.
func bindTo(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}
}
