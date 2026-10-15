package blobs

import (
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/ifbind"
)

// bindTo binds a socket to the interface (IP_BOUND_IF, IPV6_BOUND_IF): a
// dial can leave only through it. A device only dials (PlanFrom).
func bindTo(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return ifbind.ByName(iface)
}
