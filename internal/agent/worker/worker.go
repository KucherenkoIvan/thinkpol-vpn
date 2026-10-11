package worker

import (
	"context"
	"errors"
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// ErrUnsupported is returned by Run where there are no workers: they need
// Linux namespaces.
var ErrUnsupported = errors.New("worker: needs Linux")

// Session is what a sandboxed worker knows about its space and namespace.
type Session struct {
	Space netmap.SpaceID
	// Interface is the namespace's end of the veth pair to the root
	// namespace, up with Addrs and default routes via Gateways (one per
	// family). Egress and outgoing links leave through it.
	Interface string
	Addrs     []netip.Prefix
	Gateways  []netip.Addr
	// Config delivers the space's opaque configuration from the supervisor:
	// the current one first, then each change, latest-wins (an older pending
	// one is dropped). nil in Idle mode.
	Config <-chan []byte
	// Listeners delivers the supervisor's shared listeners the worker is
	// served by: the current set first, then each change, latest-wins. A
	// listener keeps its SharedListener (and its Packets or Streams) for as
	// long as it is listed.
	Listeners <-chan []SharedListener
	// SharedDrops reports what the worker dropped of what the shared
	// listeners forwarded.
	SharedDrops func() SharedDrops
	// SharedCounters delivers, every few seconds, what the supervisor's
	// shared listeners did for this space (latest-wins), for the worker's
	// sealed telemetry. Only the space's own figures.
	SharedCounters <-chan ipc.SharedCounters
}

// Serve runs a space's data plane until ctx ends. Returning early, with or
// without an error, ends the worker, and the supervisor restarts it.
type Serve func(ctx context.Context, s Session) error

// Idle serves nothing until ctx ends: the worker's data plane until `thinkpol
// up` (TP-011) composes the real one.
func Idle(ctx context.Context, _ Session) error {
	<-ctx.Done()
	return nil
}
