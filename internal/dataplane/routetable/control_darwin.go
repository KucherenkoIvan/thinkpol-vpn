package routetable

import (
	"fmt"
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/ifbind"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// physicalInterface is the interface of the family's default route; tests
// swap it.
var physicalInterface = netcfg.DefaultInterface

// SocketControl returns the Control for the transports' sockets
// (udp.Options.Control) and the direct DNS upstream's: it binds each to
// the interface of its family's default route (IP_BOUND_IF,
// IPV6_BOUND_IF), looked up as the socket opens, so it routes by that
// interface's own scoped routes and never into the TUN, whatever the split
// routes say; a link redialed after the network changed binds to the new
// interface. A socket with no default route for its family fails to open
// rather than loop through the tunnel.
func SocketControl() func(network, address string, c syscall.RawConn) error {
	return ifbind.Control(func(ipv6 bool) (ifbind.Interface, error) {
		f := netcfg.IPv4
		if ipv6 {
			f = netcfg.IPv6
		}
		name, index, err := physicalInterface(f)
		if err != nil {
			return ifbind.Interface{}, fmt.Errorf("routetable: binding a socket to the physical interface: %w", err)
		}
		return ifbind.Interface{Name: name, Index: index}, nil
	})
}
