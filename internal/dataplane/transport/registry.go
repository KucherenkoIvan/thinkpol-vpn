package transport

import (
	"context"
	"fmt"
	"net"
	"slices"
)

// ListenConfig is what a node's map says about one of its listeners: where
// it listens, and how.
type ListenConfig struct {
	// Address is the IP literal and port to listen on.
	Address string
	// Settings is the transport's own settings message for the listener
	// (camouflage target, certificate source, …).
	Settings []byte
}

// Admission is whom a listener accepts links from, and where the rest
// goes.
type Admission struct {
	Peers Peers
	// Camouflage gets what fails authentication; nil is the adapter's own
	// default (udp drops it, reality splices it to its target).
	Camouflage Camouflage
}

// Transport is one adapter, as the engine sees it: the map names it, and
// the engine checks the map's entries against it before using them.
type Transport interface {
	// Name is the transport's name in the map ("udp", "tls", …).
	Name() string
	// Network is the IP protocol its links use on the wire: "udp" or
	// "tcp" (a server's firewall lets a space dial its endpoints in it).
	Network() string
	Dialer() Dialer
	Listen(ctx context.Context, cfg ListenConfig, admission Admission) (Listener, error)
	// CheckEndpoint reports whether a dial entry of the map is usable.
	CheckEndpoint(endpoint string, cfg DialConfig) error
	// CheckInbound reports whether an inbound entry of the map is usable.
	// Listeners skip, and report, the peer links it rejects.
	CheckInbound(pl PeerLink) error
	// CheckEndpoint and CheckInbound refuse shaping the adapter can't
	// honour (ErrUnsupportedShaping) or that is invalid.
	//
	// Overhead is the most bytes the transport adds to a packet with
	// shaping s, before IP and UDP or TCP headers, apart from padding up to
	// a bucket. The path layer's MTU budget is MaxPacket, which accounts
	// for buckets too.
	Overhead(s Shaping) int
}

// Registry is the set of transports a node can use, built explicitly in the
// composition root.
type Registry struct {
	byName map[string]Transport
}

// NewRegistry registers transports; names must be unique.
func NewRegistry(transports ...Transport) (*Registry, error) {
	r := &Registry{byName: make(map[string]Transport, len(transports))}
	for _, t := range transports {
		if _, dup := r.byName[t.Name()]; dup {
			return nil, fmt.Errorf("transport: %q registered twice", t.Name())
		}
		r.byName[t.Name()] = t
	}
	return r, nil
}

// Get returns the transport the map calls name.
func (r *Registry) Get(name string) (Transport, bool) {
	t, ok := r.byName[name]
	return t, ok
}

// Names lists the registered transports, sorted.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// PacketRouter is a datagram transport's half of a server node's shared
// listener (docs/design/server-agent.md "Server agent: one worker per space"): the supervisor
// owns the public address and asks the router whose link each datagram is,
// then hands it to that space's worker. Anything not Routed goes to the
// camouflage and never reaches a worker. Rejected lists the peer links of
// the table the router can't use, e.g. two sharing a secret (both are
// dropped, not one guessed).
type PacketRouter interface {
	// RouteDatagram authenticates one datagram and reports whose link it
	// belongs to and what to do with it: only a Routed one is forwarded,
	// untouched. The identity is set for every verdict but Unknown.
	RouteDatagram(d []byte) (Identity, Verdict)
	Rejected() []PeerError
}

// StreamRouter is a stream transport's half of a shared listener, as
// PacketRouter is a datagram transport's: what every public listener of
// the transport shares (the merged table, replay state), kept across
// their reopens. ListenStream binds each public listener to it, and the
// listener routes with it (StreamListener.RouteStream).
type StreamRouter interface {
	Rejected() []PeerError
}

// StreamVerdict is a stream listener's decision on one connection.
type StreamVerdict uint8

const (
	// StreamUnknown failed authentication, or was turned away before it
	// could show who it is.
	StreamUnknown StreamVerdict = iota
	// StreamUnserved authenticated as a link of a space the caller
	// doesn't serve.
	StreamUnserved
	// StreamStale authenticated but was sealed outside the clock window,
	// or before the router started.
	StreamStale
	// StreamReplayed authenticated but was seen before (or the space's
	// replay memory is full and can't vouch for it).
	StreamReplayed
	// StreamRouted authenticated, fresh and new: handed over.
	StreamRouted
)

// StreamHandoff is a connection a stream listener authenticated, on its
// way to its space's worker (a HandoffListener).
type StreamHandoff struct {
	Peer Identity
	// Conn is the dialer's connection; Consumed what the router read from
	// it.
	Conn     net.Conn
	Consumed []byte
	// Target, if set, is a connection the router opened on Conn's behalf
	// and that goes with it (reality's target, dialled at accept), and
	// TargetRead what the router read from it and didn't pass on. What
	// was written to it is the transport's business.
	Target     net.Conn
	TargetRead []byte
}

// Close closes the handoff's connections.
func (h StreamHandoff) Close() {
	if h.Conn != nil {
		_ = h.Conn.Close()
	}
	if h.Target != nil {
		_ = h.Target.Close()
	}
}

// StreamListener is a stream transport's public listener behind a shared
// listener, as its ListenStream opened it, bound to its StreamRouter.
type StreamListener interface {
	net.Listener
	// HandoffSettings is what a worker's Handoff needs to serve the
	// connections routed from this listener: the transport's own encoding,
	// opaque to the supervisor, which passes it on as is.
	HandoffSettings() []byte
	// Camouflage is where the transport sends a connection it turns away
	// (reality's splice to its target); never nil. The caller sends there
	// what it turns away before routing.
	Camouflage() Camouflage
	// RouteStream reads the start of conn, accepted on this listener,
	// without terminating anything, and decides it. Only StreamRouted
	// comes back with connections, for the worker of the handoff's
	// space; anything else the listener turned away itself, to its
	// Camouflage, and the handoff carries only the identity it
	// authenticated as (none for StreamUnknown). serves is asked while the
	// connection is decided, so a link of a space that isn't served is
	// turned away like a stranger (StreamUnserved). waiting, if set, is
	// called at most once, when conn needs no more routing work, only its
	// dialer's bytes, and is held under the listener's own bounds: a
	// caller bounding the connections being routed lets go of this one
	// there. RouteStream returns once the connection is decided; where it
	// was turned away to runs on.
	RouteStream(conn net.Conn, serves func(Identity) bool, waiting func()) (StreamHandoff, StreamVerdict)
}

// Verdict is a PacketRouter's decision on one datagram.
type Verdict uint8

const (
	// Unknown failed authentication: it goes to the camouflage.
	Unknown Verdict = iota
	// Routed is authenticated, fresh and not seen before: forward it.
	Routed
	// Stale is authenticated but too old to deliver (sent outside the
	// clock window or before the router started, or by a sender a newer
	// one replaced): drop it.
	Stale
	// Replayed is authenticated but delivered before: drop it, so a replay
	// costs its space nothing.
	Replayed
)

// HandoffListener is a worker's listener for a stream transport behind a
// shared listener: the supervisor accepted and routed the connection and
// passes it on as its router handed it over. ServeStream owns h's
// connections from then on, and returns at once: the worker hands it
// every connection of the listener in turn.
type HandoffListener interface {
	Listener
	ServeStream(h StreamHandoff)
}

// PacketRoutable is a datagram transport behind a shared listener. The
// supervisor opens the public socket with ListenPacket, routes every datagram
// it reads with the PacketRouter and forwards it untouched to its space's
// worker; the worker serves what it is forwarded with ListenForwarded, whose
// replies go back out through the supervisor's socket.
type PacketRoutable interface {
	Transport
	// PacketRouter routes for peers, following their changes.
	PacketRouter(peers Peers) PacketRouter
	// ListenPacket opens the public UDP socket a listener of the map
	// describes, checking its settings as Listen would.
	ListenPacket(ctx context.Context, cfg ListenConfig) (*net.UDPConn, error)
	// ListenForwarded listens on pc, which it owns from then on:
	// datagrams the supervisor routed to this worker in, replies out.
	ListenForwarded(pc net.PacketConn, admission Admission) (Listener, error)
}

// StreamRoutable is a stream transport behind a shared listener. The
// supervisor accepts connections on the public listener ListenStream
// opens, has it route each (it reads the start of the connection) and
// passes what it hands over to its space's worker, whose
// Handoff listener takes it from there.
type StreamRoutable interface {
	Transport
	// StreamRouter is the routing state for peers, following their
	// changes, shared by the transport's listeners.
	StreamRouter(peers Peers) StreamRouter
	// ListenStream opens the public listener a listener of the map
	// describes, checking its settings as Listen would, routing with
	// router; a router of another transport is an error.
	ListenStream(ctx context.Context, cfg ListenConfig, router StreamRouter) (StreamListener, error)
	// Handoff is a worker's listener for the connections the supervisor
	// passes on from one public listener, address being where that
	// listener is bound and settings its HandoffSettings.
	Handoff(address string, settings []byte, admission Admission) (HandoffListener, error)
}
