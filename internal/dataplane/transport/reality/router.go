package reality

import (
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// This file is the decision on a hello: the router's table and replay
// cache behind a shared listener (in the supervisor), and the check every
// reality listener runs on a whole hello. public.go is the rest of the
// supervisor's side, handoff.go the worker's.

// StreamRouter implements transport.StreamRoutable: one router serves
// every reality listener of a supervisor, so the replay cache is per
// credential, not per listener, and outlives a listener's reopening.
func (t *Transport) StreamRouter(peers transport.Peers) transport.StreamRouter {
	return &router{t: t, peers: peers, check: helloCheck{
		t:      t,
		replay: newReplays(transport.MaxClockSkew), // the widest window
		start:  transport.StartedAt(t.now(), t.elapsed),
	}}
}

// router is the supervisor's half of reality behind a shared listener:
// the merged table and the replay cache its public listeners decide each
// hello against, before anything is answered or any TLS terminated.
type router struct {
	t     *Transport
	peers transport.Peers
	check helloCheck

	mu      sync.Mutex
	tab     table
	changed <-chan struct{} // nil until the table was first read
}

func (r *router) Rejected() []transport.PeerError {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	return r.tab.rejected
}

// refresh rebuilds the table if the peers changed since it was read; r.mu
// held.
func (r *router) refresh() {
	if r.changed != nil {
		select {
		case <-r.changed:
		default:
			return
		}
	}
	var links []transport.PeerLink
	links, r.changed = r.peers.Snapshot()
	r.tab = newTable(r.t, links, r.tab.links)
	spaces := map[transport.SpaceID]bool{}
	for _, pl := range r.tab.links {
		spaces[pl.Peer.Space] = true
	}
	r.check.replay.prune(spaces, r.t.now())
}

func (r *router) lookup(id shortID) (transport.PeerLink, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	pl, ok := r.tab.links[id]
	return pl, ok
}

// helloCheck decides a whole hello for a listener: a router's, a
// standalone listener's, or a worker's behind a router, which admitted
// the hello once already and so has neither a replay cache nor a start
// rule.
type helloCheck struct {
	t      *Transport
	replay *replays            // nil behind a router
	start  transport.StartRule // the zero rule behind a router
}

// check decides record, a whole hello, for a listener with settings ls:
// its seal opens under ls's key and names a short id lookup finds, whose
// space serves (nil: any), sealed within ls's window and not before the
// start rule's second, and, with a replay cache, not seen before.
func (c helloCheck) check(ls listenSettings, record []byte, lookup func(shortID) (transport.PeerLink, bool), serves func(transport.Identity) bool) (shortID, transport.Identity, transport.StreamVerdict) {
	h, sh, ok := ls.openHello(record)
	if !ok {
		return shortID{}, transport.Identity{}, transport.StreamUnknown
	}
	pl, ok := lookup(sh.shortID)
	if !ok {
		return shortID{}, transport.Identity{}, transport.StreamUnknown
	}
	if serves != nil && !serves(pl.Peer) {
		return sh.shortID, pl.Peer, transport.StreamUnserved
	}
	now := c.t.now()
	if !transport.FreshWithin(sh.sent, now, ls.window) || c.start.Refuses(sh.sent, now) {
		return sh.shortID, pl.Peer, transport.StreamStale
	}
	if c.replay != nil && !c.replay.admit(pl.Peer.Space, sh.shortID, h.sessionID, sh.sent, now) {
		return sh.shortID, pl.Peer, transport.StreamReplayed
	}
	return sh.shortID, pl.Peer, transport.StreamRouted
}
