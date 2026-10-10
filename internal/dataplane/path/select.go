package path

import "time"

// Candidate is one candidate hop (a peer's first hop, or a relay's next
// hop toward a destination) as the path layer sees it when a packet is
// about to leave.
type Candidate struct {
	Hop NodeID
	// Up: a link to Hop delivered something within Options.DeadAfter, and
	// the Bind hasn't demoted Hop for this peer (see Options.E2EDead).
	Up bool
	// UpFor is how long Hop has been up without a gap; zero when down.
	UpFor time.Duration
	// Linked: a link to Hop exists, up or not yet heard from.
	Linked bool
	// RTT is the link's smoothed probe round trip; zero until measured.
	RTT time.Duration
	// HeardVia is how long ago the latest WireGuard-shaped packet from the
	// far end (the peer, or the route's destination) arrived through Hop;
	// negative if none has. Arrivals aren't authenticated: an adjacent
	// node can claim any source it may route for.
	HeardVia time.Duration
	// Followed: this end follows the far end (see Failover) and the far
	// end's traffic comes through Hop, within Options.FollowFor. For a
	// Bind, that is the path of the latest packet WireGuard authenticated
	// and adopted as the peer's endpoint.
	Followed bool
}

// Selector picks the hop for the next packet. Candidates come in the map's
// priority order; current is the hop picked last time (zero at first). It
// reports false when no candidate is usable.
//
// It is called for every batch a Bind sends and every packet a relay
// forwards on a route with several next hops, under that peer's or route's
// lock, and must not keep cands. A selector with state of its own must be
// passed again, the same value, to every SetPeers or Update that keeps the
// peer or route: the path layer keeps only current.
type Selector interface {
	Select(current NodeID, cands []Candidate) (NodeID, bool)
}

// Failover follows the priority order with hysteresis:
//   - the hop the far end's traffic comes through (Followed), if it is up
//     here too;
//   - otherwise the current hop while it is up; a hop earlier in the order
//     takes over only once it has been up for HoldDown, so a flapping
//     primary doesn't pull traffic back and forth;
//   - otherwise the first hop that is up, then the first with a link at
//     all (its liveness not known yet).
//
// Exactly one end of a pair follows: the end with the higher node id. The
// lower one leads with the rules above minus the first, so a pair can't
// chase each other's choices; the leader returns to its primary after
// HoldDown and the follower comes along.
type Failover struct {
	HoldDown time.Duration
}

func (f Failover) Select(current NodeID, cands []Candidate) (NodeID, bool) {
	for _, c := range cands {
		if c.Followed && c.Up {
			return c.Hop, true
		}
	}
	for i, c := range cands {
		if c.Hop != current || !c.Up {
			continue
		}
		for _, better := range cands[:i] {
			if better.Up && better.UpFor >= f.HoldDown {
				return better.Hop, true
			}
		}
		return current, true
	}
	for _, c := range cands {
		if c.Up {
			return c.Hop, true
		}
	}
	for _, c := range cands {
		if c.Linked {
			return c.Hop, true
		}
	}
	return NodeID{}, false
}
