package dns

import (
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/ifbind"
)

// BindToInterface is a socket Control that binds sockets to the named
// interface (SO_BINDTODEVICE on Linux, IP_BOUND_IF on macOS): what they
// send leaves through it or not at all, whatever the routes say. Where
// sockets can't be bound, they fail rather than leave unbound.
func BindToInterface(name string) func(network, address string, c syscall.RawConn) error {
	return ifbind.ByName(name)
}
