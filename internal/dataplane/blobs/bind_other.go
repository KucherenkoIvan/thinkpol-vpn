//go:build !linux && !android

package blobs

import (
	"errors"
	"syscall"
)

// bindTo refuses an interface: binding sockets to the TUN keeps the service
// to the tunnel, and the platforms with a data plane on the way (TP-019,
// TP-047) bring their own (IP_BOUND_IF, IP_UNICAST_IF).
func bindTo(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("blobs: binding a socket to the overlay's interface is not implemented on this platform")
	}
}
