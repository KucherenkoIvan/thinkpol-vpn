package path

import "time"

// Candidate is one candidate hop (a peer's first hop, or a relay's next
// hop toward a destination) as the path layer sees it when a packet is
// about to leave.
type Candidate struct {
	Hop NodeID
	// Up: a link to Hop answered a probe within Options.DeadAfter.
	Up bool
	// UpFor is how long Hop has been up without a gap; zero when down.
	UpFor time.Duration
	// Linked: a link to Hop exists, up or not yet proven.
	Linked bool
	// RTT is the link's smoothed probe round trip, an upper bound (see
	// transport.MaxControlHold); zero until measured.
	RTT time.Duration
	// HeardVia is how long ago the latest WireGuard-shaped packet from the
	// peer arrived through Hop; negative if none has, and always for a
	// relay's next hops. Arrivals aren't authenticated: an adjacent node
	// can claim any source it may carry.
	HeardVia time.Duration
	// Followed: this end follows the peer (Choice.Follows), and the latest
	// packet WireGuard authenticated from the peer came through Hop, within
	// Options.FollowFor.
	Followed bool
}

// Choice is what a Selector chooses from.
type Choice struct {
	// Current is the hop picked last time (zero at first).
	Current NodeID
	// Follows: this end of a pair follows the other (it has the higher
	// node id). The other end leads; relays never follow.
	Follows bool
	// Candidates come in the map's priority order. A Selector must not
	// keep the slice.
	Candidates []Candidate
}

// Selector picks the hop for the next packet, and reports false when no
// candidate is usable. It is called for every batch a Bind sends and every
// packet a relay forwards, under that peer's or route's lock. A selector
// with state of its own must be passed again, the same value, to every
// SetPeers or Update that keeps the peer or route: the path layer keeps
// only Current.
type Selector interface {
	Select(c Choice) (NodeID, bool)
}

// Failover follows the priority order with hysteresis. A leader (and a
// relay):
//   - stays on the current hop while it is up; a hop earlier in the order
//     takes over only once it has been up for HoldDown, so a flapping
//     primary doesn't pull traffic back and forth;
//   - otherwise takes the first hop that is up, then the first with a link
//     at all (not proven yet).
//
// A follower takes the hop the leader's traffic comes through (Followed)
// if it is up here too; otherwise it stays on the current hop while that is
// up, never returning to its primary on its own (the leader decides that),
// and otherwise takes the first hop that is up, then the first linked.
type Failover struct {
	HoldDown time.Duration
}

func (f Failover) Select(c Choice) (NodeID, bool) {
	cands := c.Candidates
	if c.Follows {
		for _, cand := range cands {
			if cand.Followed && cand.Up {
				return cand.Hop, true
			}
		}
	}
	for i, cand := range cands {
		if cand.Hop != c.Current || !cand.Up {
			continue
		}
		if !c.Follows {
			for _, better := range cands[:i] {
				if better.Up && better.UpFor >= f.HoldDown {
					return better.Hop, true
				}
			}
		}
		return c.Current, true
	}
	for _, cand := range cands {
		if cand.Up {
			return cand.Hop, true
		}
	}
	for _, cand := range cands {
		if cand.Linked {
			return cand.Hop, true
		}
	}
	return NodeID{}, false
}
