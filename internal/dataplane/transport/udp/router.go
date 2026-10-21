package udp

import (
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

	admitLadder

	mu      sync.Mutex
	set     *peerSet
	changed <-chan struct{}
	table   *senderHistories
	scratch []byte
}

var _ transport.PacketRouter = (*Router)(nil)

func newRouter(t *Transport, peers transport.Peers) *Router {
	return &Router{t: t, peers: peers, table: newSenderHistories(), scratch: make([]byte, 0, maxDatagram)}
}

// RouteDatagram implements transport.PacketRouter.
func (r *Router) RouteDatagram(d []byte) (transport.Identity, transport.Verdict) {
	now := r.t.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh(now)
	e, o, v := r.admit(r.scratch[:0], r.set, r.table, d, now)
	switch v {
	case dropUnauthenticated:
		// No connection id in the table, or the tag failed under the one
		// it matched: not routed anywhere, and not named even when the
		// id matched.
		return transport.Identity{}, transport.Unknown
	case dropStaleTimestamp, dropStale:
		return e.link.Peer, transport.Stale
	case dropReplay:
		return e.link.Peer, transport.Replayed
	}
	r.counters.received(o.packets)
	return e.link.Peer, transport.Routed
}

// Counters reports what the router routed (Delivered and Cover, as a
// listener counts them) and what it turned away and why.
func (r *Router) Counters() Counters { return r.counters.snapshot() }

// Rejected implements transport.PacketRouter.
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
	r.table.follow(r.set, now)
}
