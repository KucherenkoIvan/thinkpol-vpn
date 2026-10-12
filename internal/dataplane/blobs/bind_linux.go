//go:build linux && !android

package blobs

import (
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/ifbind"
)

// bindTo binds a socket to the interface (SO_BINDTODEVICE): a listener then
// takes only what arrives through it, and a dial can leave only through it.
func bindTo(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return ifbind.ByName(iface)
}
