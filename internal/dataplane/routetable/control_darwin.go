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
// IPV6_BOUND_IF), looked up as the socket opens, so it never routes into
// the TUN; a link redialed after the network changed binds to the new
// interface. A socket with no default route for its family fails to open
// rather than loop through the tunnel. A bound socket reaches only
// destinations whose own route is on that interface (an on-link subnet,
// the layout's endpoint and direct routes): the primary interface has no
// scoped default route of its own, so for a destination the split routes
// send into the utun the kernel answers EHOSTUNREACH (seen on a device:
// `ping -b en0` to a tunneled address).
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
