package agent

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

// Transports is the node's transport registry: every transport a map may
// name. Supervisor, worker and device build it the same way.
//
// Sockets aren't marked yet: in M0 only the overlay ranges are routed into
// the TUN, so links can't loop through it. TP-018 adds the socket Control
// (udp.Options.Control) here when route-table rules send everything else
// into the TUN.
func Transports() (*transport.Registry, error) {
	return transport.NewRegistry(udp.New(udp.Options{}))
}
