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
	Peers      Peers
	Camouflage Camouflage // nil drops everything unauthenticated
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
// PacketRouter is a datagram transport's: it says whose link each new
// connection is.
type StreamRouter interface {
	// RouteStream reads the start of a new connection (for tls, the
	// ClientHello) without terminating anything, and reports whose link it
	// is and the bytes it consumed.
	RouteStream(conn net.Conn) (peer Identity, consumed []byte, ok bool)
	Rejected() []PeerError
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
// passes it on with the bytes its router consumed.
type HandoffListener interface {
	Listener
	ServeStream(conn net.Conn, consumed []byte)
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
// supervisor accepts connections on the public listener ListenStream opens,
// routes each with the StreamRouter (which reads the start of the
// connection) and passes the connection, with the bytes the router
// consumed, to its space's worker, whose Handoff listener takes it from
// there.
type StreamRoutable interface {
	Transport
	// StreamRouter routes for peers, following their changes.
	StreamRouter(peers Peers) StreamRouter
	// ListenStream opens the public listener a listener of the map
	// describes.
	ListenStream(ctx context.Context, cfg ListenConfig) (net.Listener, error)
	// Handoff is a worker's listener for the connections the supervisor
	// passes on. The listener's settings stay with the supervisor's public
	// listener (ListenStream): a worker's shared listener doesn't carry
	// them yet, so a transport whose handoff needs them (tls, TP-028)
	// adds them to the shared listener's message first.
	Handoff(admission Admission) (HandoffListener, error)
}
