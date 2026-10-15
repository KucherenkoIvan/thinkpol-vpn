//go:build !linux && !android && !darwin

package blobs

import (
	"errors"
	"syscall"
)

// bindTo refuses an interface: binding sockets to the TUN keeps the service
// to the tunnel, and Windows brings its own with its data plane (TP-047,
// IP_UNICAST_IF).
func bindTo(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("blobs: binding a socket to the overlay's interface is not implemented on this platform")
	}
}
