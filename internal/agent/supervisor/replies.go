package supervisor

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// replyWindow is how long a remote end a link's live datagram came from
	// stays a destination for the worker's replies. It is refreshed by
	// every authenticated, fresh, non-replayed datagram, so an active link
	// never loses it: WireGuard sends at least every 2 minutes on a live
	// session (rekeys, and keepalives when configured), and the path
	// layer probes each link every 2 s. NAT mappings expire on a similar
	// scale, so an address quiet for longer is likely gone anyway.
	replyWindow = 2 * time.Minute
	// replyPeersPerLink bounds the remote ends one link keeps; a new one
	// evicts that link's oldest, never another link's.
	replyPeersPerLink = 8
	// replySweep is how often, at most, a space's expired remote ends are
	// swept: expiry is exact to within this.
	replySweep = 10 * time.Second
)

// route is one space's way to its current worker, across the worker's
// restarts.
type route struct {
	space    transport.SpaceID
	end      atomic.Pointer[workerSockets] // nil while no worker runs
	counters counters
	// peers is the reply tracker: where the worker's replies may go.
	peers replyPeers
}

// replyPeers owns the space's reply tracker: the remote ends the worker
// may answer, per link, bounded and expiring.
type replyPeers struct {
	mu      sync.Mutex
	links   map[transport.NodeID]*linkRemotes
	remotes map[replyKey]*remote
	swept   time.Time
}

func newReplyPeers() replyPeers {
	return replyPeers{links: map[transport.NodeID]*linkRemotes{}, remotes: map[replyKey]*remote{}}
}

// replyKey is a remote end as the worker names it: the listener, and the
// address unmapped and without a zone (the IPC header carries neither).
type replyKey struct {
	listener uint32
	addr     netip.AddrPort
}

func keyOf(listener uint32, a netip.AddrPort) replyKey {
	return replyKey{listener, netip.AddrPortFrom(a.Addr().Unmap().WithZone(""), a.Port())}
}

// remote is a remote end some of the space's links came from.
type remote struct {
	holders int            // links holding it
	at      time.Time      // its latest refresh by any of them
	to      netip.AddrPort // as received, zone included: where replies go
}

// linkRemotes are one link's latest remote ends.
type linkRemotes struct {
	n       int
	entries [replyPeersPerLink]struct {
		key replyKey
		at  time.Time
	}
}

// remember makes the remote end of a live datagram of link node a
// destination for the space's replies for replyWindow. The link keeps its
// latest replyPeersPerLink remote ends; a new one evicts the link's
// oldest, which remember reports.
func (p *replyPeers) remember(node transport.NodeID, key replyKey, to netip.AddrPort, now time.Time) (evicted bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweep(now)
	lr := p.links[node]
	if lr == nil {
		lr = &linkRemotes{}
		p.links[node] = lr
	}
	if rm := p.remotes[key]; rm != nil {
		for i := range lr.n {
			if lr.entries[i].key == key {
				lr.entries[i].at = now
				rm.at, rm.to = now, to
				return false
			}
		}
	}
	if lr.n == replyPeersPerLink {
		oldest := 0
		for i := 1; i < lr.n; i++ {
			if lr.entries[i].at.Before(lr.entries[oldest].at) {
				oldest = i
			}
		}
		p.release(lr.entries[oldest].key)
		lr.n--
		lr.entries[oldest] = lr.entries[lr.n]
		evicted = true
	}
	lr.entries[lr.n].key, lr.entries[lr.n].at = key, now
	lr.n++
	rm := p.remotes[key]
	if rm == nil {
		rm = &remote{}
		p.remotes[key] = rm
	}
	rm.holders++
	rm.at, rm.to = now, to
	return evicted
}

// release drops one link's hold on a remote end; p.mu held.
func (p *replyPeers) release(key replyKey) {
	if rm := p.remotes[key]; rm != nil {
		if rm.holders--; rm.holders <= 0 {
			delete(p.remotes, key)
		}
	}
}

// sweep drops expired remote ends, at most once per replySweep; p.mu held.
func (p *replyPeers) sweep(now time.Time) {
	if now.Sub(p.swept) < replySweep {
		return
	}
	p.swept = now
	for node, lr := range p.links {
		for i := 0; i < lr.n; {
			if now.Sub(lr.entries[i].at) <= replyWindow {
				i++
				continue
			}
			p.release(lr.entries[i].key)
			lr.n--
			lr.entries[i] = lr.entries[lr.n]
		}
		if lr.n == 0 {
			delete(p.links, node)
		}
	}
}

// replyTo is where a reply to key goes, if the worker may send one.
func (p *replyPeers) replyTo(key replyKey, now time.Time) (netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rm := p.remotes[key]
	if rm == nil || now.Sub(rm.at) > replyWindow {
		return netip.AddrPort{}, false
	}
	return rm.to, true
}

// reply sends a datagram a space's worker wrote out through the public
// socket it names. A worker may only answer: the destination must be a
// remote end one of its own links' live (authenticated, fresh, not
// replayed) datagrams came from, through that listener, within
// replyWindow. So a worker can't use the node's public address to reach
// anyone else, whatever egress its space has.
func (s *shared) reply(space transport.SpaceID, h ipc.DatagramHeader, d []byte) {
	r := (*s.routes.Load())[space]
	if r == nil {
		return
	}
	pl := (*s.byID.Load())[h.Listener]
	if pl == nil || pl.udp == nil {
		r.counters.repliesNoListener.Add(1)
		return
	}
	to, ok := r.peers.replyTo(keyOf(h.Listener, h.Remote), s.now())
	if !ok {
		r.counters.repliesNotAllowed.Add(1)
		return
	}
	if s.fair != nil && !s.fair.Allow(space, len(d)) {
		r.counters.repliesOverShare.Add(1)
		return
	}
	if _, err := pl.udp.WriteToUDPAddrPort(d, to); err != nil {
		r.counters.replyErrors.Add(1)
		return
	}
	r.counters.replies.Add(1)
	r.counters.replyBytes.Add(uint64(len(d)))
	if s.fair != nil {
		s.fair.Charge(space, len(d))
	}
}
