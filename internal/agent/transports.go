package agent

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

// Transports is the node's transport registry: every transport a map may
// name.
//
// With markSockets, every link's socket carries routetable.Mark on Linux
// and is bound to the physical interface on macOS
// (routetable.SocketControl), so it bypasses the TUN however the route
// table routes its destination: a device's links, where route-table
// mode sends everything else into the TUN. A server's workers don't mark
// (their namespaces route nothing into the TUN, and marking needs
// CAP_NET_ADMIN over the namespace). Never WireGuard: it has no sockets.
func Transports(markSockets bool) (*transport.Registry, error) {
	var o udp.Options
	if markSockets {
		o.Control = routetable.SocketControl()
	}
	return transport.NewRegistry(udp.New(o))
}
