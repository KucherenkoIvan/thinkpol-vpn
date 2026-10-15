package udp

import (
	"net"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Router routes datagrams for a shared listener (DESIGN.md "Server agent:
// one worker per space"): it finds the credential by connection id,
// authenticates the datagram, checks its timestamp and filters replays per
// credential exactly as a Listener does, then the supervisor forwards it
// untouched to the worker of the space it belongs to. The worker's
// Listener decrypts again and filters again; at our packet rates the
// second decryption costs nothing worth saving. Filtering here means a
// replay, which anyone with a passive tap can send, never reaches a worker
// or costs its space anything.
//
// Its sender history is per credential and outlives table changes, as a
// Listener's does. One Router serves every socket of the transport (the
// supervisor keeps one per transport, across its listeners' reopens), so a
// datagram replayed to another listener is still a replay. Only a new
// Router (a supervisor restart) routes replays of datagrams sent in the
// last ten minutes once more — five, if the sender's clock was right —
// which the worker's Listener, if it kept running, still drops.
// A Router is safe for concurrent use.
type Router struct {
	t     *Transport
	peers transport.Peers

	mu       sync.Mutex
	set      *peerSet
	changed  <-chan struct{}
	senders  map[string]*senders // by secret
	retired  map[string]retiree  // senders of secrets gone from the table
	scratch  []byte
	counters counters
}

var _ transport.Router = (*Router)(nil)

func newRouter(t *Transport, peers transport.Peers) *Router {
	return &Router{t: t, peers: peers, senders: map[string]*senders{}, retired: map[string]retiree{}, scratch: make([]byte, 0, maxDatagram)}
}

// RouteDatagram implements transport.Router.
func (r *Router) RouteDatagram(d []byte) (transport.Identity, transport.Verdict) {
	id, ok := idOf(d)
	if !ok {
		r.counters.unauthenticated.Add(1)
		return transport.Identity{}, transport.Unknown
	}
	now := r.t.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh(now)
	e := r.set.lookup(id, epochOf(now))
	if e == nil {
		r.counters.unauthenticated.Add(1)
		return transport.Identity{}, transport.Unknown
	}
	o, err := open(r.scratch[:0], e.recv, d)
	switch {
	case err != nil:
		r.counters.unauthenticated.Add(1)
		return transport.Identity{}, transport.Unknown
	case !o.fresh(now):
		r.counters.staleTimestamp.Add(1)
		return e.link.Peer, transport.StaleClock
	}
	switch r.senders[string(e.link.Verifier)].admit(o.sender, o.counter, o.sent, now) {
	case dropReplay:
		r.counters.replayed.Add(1)
		return e.link.Peer, transport.Replayed
	case dropStale:
		r.counters.staleSender.Add(1)
		return e.link.Peer, transport.StaleSender
	}
	r.counters.received(o.packets)
	return e.link.Peer, transport.Routed
}

// RouteStream implements transport.Router: udp has no streams.
func (r *Router) RouteStream(net.Conn) (transport.Identity, []byte, bool) {
	return transport.Identity{}, nil, false
}

// Counters reports what the router routed (Delivered and Cover, as a
// listener counts them) and what it turned away and why.
func (r *Router) Counters() Counters { return r.counters.snapshot() }

// Rejected implements transport.Router.
func (r *Router) Rejected() []transport.PeerError {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh(r.t.now())
	return r.set.problems()
}

// refresh picks up a changed table, keeping each secret's sender history
// (and a removed one's for as long as its datagrams stay fresh), so neither
// a table change nor taking a secret out and back reopens it to replays.
func (r *Router) refresh(now time.Time) {
	if r.set != nil {
		select {
		case <-r.changed:
		default:
			return
		}
	}
	var links []transport.PeerLink
	links, r.changed = r.peers.Snapshot()
	r.set = indexPeers(links, epochOf(now))
	for key, rt := range r.retired {
		if !sentFresh(rt.senders.newest, now) {
			delete(r.retired, key)
		}
	}
	for key, s := range r.senders {
		if r.set.bySecret[key] == nil {
			r.retired[key] = retiree{senders: s}
			delete(r.senders, key)
		}
	}
	for key := range r.set.bySecret {
		if r.senders[key] != nil {
			continue
		}
		if rt, ok := r.retired[key]; ok {
			r.senders[key] = rt.senders
			delete(r.retired, key)
			continue
		}
		r.senders[key] = &senders{}
	}
}
