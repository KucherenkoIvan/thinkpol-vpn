package path

import "time"

// Candidate is one candidate first hop toward a peer, as the path layer
// sees it when a packet is about to leave.
type Candidate struct {
	Hop NodeID
	// Up: a link to Hop delivered something within Options.DeadAfter.
	Up bool
	// UpFor is how long Hop has been up without a gap; zero when down.
	UpFor time.Duration
	// Linked: a link to Hop exists, up or not yet heard from.
	Linked bool
	// RTT is the link's smoothed probe round trip; zero until measured.
	RTT time.Duration
	// Followed: the peer's latest authenticated packets arrived through
	// Hop, within Options.FollowFor. The peer's side of that path works.
	Followed bool
}

// Selector picks a peer's first hop for the next packet. Candidates come in
// the map's priority order; current is the hop picked last time (zero at
// first). It reports false when no candidate is usable.
//
// It is called for every batch WireGuard sends, under the peer's lock, and
// must not keep cands. Scoring policies for hop groups (lowest latency,
// spread) are Selectors too.
type Selector interface {
	Select(current NodeID, cands []Candidate) (NodeID, bool)
}

// Failover follows the priority order with hysteresis:
//   - a hop the peer's own traffic comes through, if it is up here too, so
//     both ends converge on a path that works on both sides of the relay;
//   - otherwise the current hop while it is up; a hop earlier in the order
//     takes over only once it has been up for HoldDown, so a flapping
//     primary doesn't pull traffic back and forth;
//   - otherwise the first hop that is up, then the first with a link at
//     all (its liveness not known yet).
//
// While the peer keeps talking, following it wins over HoldDown: a pair that
// failed over stays on the path that works until that one fails too.
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
