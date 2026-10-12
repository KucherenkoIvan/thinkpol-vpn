//go:build linux && !android

package routetable

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SocketControl returns the Control for the transports' sockets
// (udp.Options.Control): it sets Mark (SO_MARK, which needs
// CAP_NET_ADMIN), so a link's packets skip Table and leave by the main
// table. A socket it can't mark fails to open rather than loop through
// the tunnel.
func SocketControl() func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, Mark)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("routetable: mark socket: %w", serr)
		}
		return nil
	}
}
