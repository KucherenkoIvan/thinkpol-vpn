package udp

import (
	"net"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Router routes datagrams for a shared listener (DESIGN.md "Server agent:
// one worker per space"): it finds the credential by connection id,
// authenticates the datagram and checks its timestamp, then the supervisor
// forwards it untouched to the worker of the space it belongs to. The
// worker's Listener decrypts again and filters replays; at our packet rates
// the second decryption costs nothing worth saving.
type Router struct {
	t     *Transport
	peers transport.Peers

	mu       sync.Mutex
	set      *peerSet
	changed  <-chan struct{}
	scratch  []byte
	counters counters
}

var _ transport.Router = (*Router)(nil)

func newRouter(t *Transport, peers transport.Peers) *Router {
	return &Router{t: t, peers: peers, scratch: make([]byte, 0, innerSize+transport.MaxPacketSize)}
}

// RouteDatagram implements transport.Router.
func (r *Router) RouteDatagram(d []byte) (transport.Identity, bool) {
	id, ok := idOf(d)
	if !ok {
		r.counters.unauthenticated.Add(1)
		return transport.Identity{}, false
	}
	now := r.t.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	e := r.set.lookup(id, epochOf(now))
	if e == nil {
		r.counters.unauthenticated.Add(1)
		return transport.Identity{}, false
	}
	o, err := open(r.scratch[:0], e.recv, d)
	switch {
	case err != nil:
		r.counters.unauthenticated.Add(1)
		return transport.Identity{}, false
	case !o.fresh(now):
		r.counters.staleTimestamp.Add(1)
		return transport.Identity{}, false
	}
	r.counters.delivered.Add(1)
	return e.link.Peer, true
}

// RouteStream implements transport.Router: udp has no streams.
func (r *Router) RouteStream(net.Conn) (transport.Identity, []byte, bool) {
	return transport.Identity{}, nil, false
}

// Counters reports what the router turned away and why ("delivered" counts
// datagrams routed).
func (r *Router) Counters() Counters { return r.counters.snapshot() }

// Rejected lists the peer links of the table the router can't use.
func (r *Router) Rejected() []transport.PeerError {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	return r.set.problems()
}

func (r *Router) refresh() {
	if r.set != nil {
		select {
		case <-r.changed:
		default:
			return
		}
	}
	var links []transport.PeerLink
	links, r.changed = r.peers.Snapshot()
	r.set = indexPeers(links, epochOf(r.t.now()))
}
