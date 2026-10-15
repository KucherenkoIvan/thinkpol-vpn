package udp

import "time"

// replayWindow accepts each counter at most once, and none older than the
// window behind the highest seen (a bitmap ring, as in RFC 6479). Only
// authenticated counters may be offered, or a forger could slide it.
type replayWindow struct {
	started bool
	highest uint64
	ring    [replayWords]uint64
}

const (
	replayWords = 32
	// replayWindowSize is how far behind the highest counter a packet may
	// still arrive; one ring word is kept free for the sliding edge.
	replayWindowSize = (replayWords - 1) * 64
)

func (w *replayWindow) accept(counter uint64) bool {
	switch {
	case !w.started:
		w.started = true
		w.ring = [replayWords]uint64{}
		w.highest = counter
	case counter > w.highest:
		cur, next := w.highest/64, counter/64
		for i, n := uint64(1), min(next-cur, replayWords); i <= n; i++ {
			w.ring[(cur+i)%replayWords] = 0
		}
		w.highest = counter
	case w.highest-counter >= replayWindowSize:
		return false
	}
	word, bit := (counter/64)%replayWords, uint64(1)<<(counter%64)
	if w.ring[word]&bit != 0 {
		return false
	}
	w.ring[word] |= bit
	return true
}

// senders is a receiver's view of the senders of one credential: a replay
// window for each of the last few, and which one is current. A dialer that
// redials, or a listener that restarts, is a new sender with counters from
// zero and a later creation time.
//
// Every sender that ever showed up is remembered for as long as its
// datagrams can stay fresh (senderForget, twice maxClockSkew: the sealed
// send time is the sender's, up to a skew ahead of the receiver's clock):
// in a slot, with the counters seen, even when it was refused; or, once
// evicted from the slots, by id alone, refused outright. So a replay can't
// come back later as a "new" sender once the current one goes quiet. The
// evicted are at most maxEvicted, the oldest forgotten first: a dialer
// churning through senders can't make this grow, or cost more per
// datagram, without bound. A forgotten sender is older than the churning
// current one, so while that one is active it is still refused; the
// residual: a sender evicted from the slots and then pushed out of the
// ring by more than maxEvicted further evictions within ten minutes can
// take over again once the current sender has been silent for
// senderTakeover (30 s), and making those evictions requires the
// credential.
type senders struct {
	tick    uint64
	entries [maxSenders]senderEntry
	current *senderEntry
	seen    time.Time // last datagram accepted from current
	evicted evictedSenders
}

// evictedSenders are the ids of senders evicted from the slots, refused
// for senderForget after: a map for lookups and a ring in eviction order,
// so expiry and the bound cost O(1) per eviction.
type evictedSenders struct {
	at         map[senderID]time.Time
	ring       []evictedSender
	head, size int
}

type evictedSender struct {
	id senderID
	at time.Time
}

// maxEvicted bounds a credential's evicted senders.
const maxEvicted = 1024

// senderForget is how long a receiver remembers a sender id it will not
// accept: one evicted from the slots, or a retired flow's. A datagram is
// accepted within maxClockSkew of its sealed send time on the sender's
// clock, and a sender was last seen no later than its eviction, so a
// datagram sealed as it was evicted, by a sender clocked ahead by the full
// skew, stays fresh twice the skew past the eviction on the receiver's
// clock. Forgetting earlier would let a replay of it come back as a "new"
// sender and take the link over; past twice the skew its datagrams are
// stale whatever the sender's clock.
const senderForget = 2 * maxClockSkew

func (e *evictedSenders) add(id senderID, now time.Time) {
	e.expire(now)
	if e.ring == nil {
		e.at = make(map[senderID]time.Time)
		e.ring = make([]evictedSender, maxEvicted)
	}
	if e.size == len(e.ring) {
		e.pop()
	}
	e.ring[(e.head+e.size)%len(e.ring)] = evictedSender{id, now}
	e.size++
	e.at[id] = now
}

func (e *evictedSenders) pop() {
	old := e.ring[e.head]
	if at, ok := e.at[old.id]; ok && at.Equal(old.at) {
		delete(e.at, old.id)
	}
	e.head = (e.head + 1) % len(e.ring)
	e.size--
}

func (e *evictedSenders) expire(now time.Time) {
	for e.size > 0 && now.Sub(e.ring[e.head].at) > senderForget {
		e.pop()
	}
}

func (e *evictedSenders) has(id senderID, now time.Time) bool {
	at, ok := e.at[id]
	return ok && now.Sub(at) <= senderForget
}

const (
	maxSenders = 8
	// senderTakeover is how long the current sender must be silent before
	// an older one may take over (a dialer whose clock went back).
	senderTakeover = 30 * time.Second
)

type senderEntry struct {
	id      senderID
	used    uint64 // tick of last use; 0 = empty
	refused bool   // turned away as older than the current sender
	window  replayWindow
}

// verdict is what a receiver does with an authenticated, fresh datagram.
type verdict int

const (
	dropReplay    verdict = iota // a counter seen before or behind the window
	dropStale                    // a sender older than the current one, or forgotten
	deliver                      // deliver, but don't move the reply address
	deliverNewest                // deliver; the current sender's newest counter
)

func (s *senders) admit(id senderID, counter uint64, now time.Time) verdict {
	s.tick++
	var e, victim *senderEntry
	for i := range s.entries {
		c := &s.entries[i]
		if c.used != 0 && c.id == id {
			e = c
			break
		}
		if c != s.current && (victim == nil || c.used < victim.used) {
			victim = c
		}
	}
	if e == nil {
		if s.evicted.has(id, now) {
			return dropStale
		}
		if victim.used != 0 {
			s.evicted.add(victim.id, now)
		}
		*victim = senderEntry{id: id, refused: true}
		e = victim
	}
	quiet := s.current == nil || now.Sub(s.seen) > senderTakeover
	takesOver := s.current == nil || id.created() > s.current.id.created() || quiet
	newest := !e.window.started || counter > e.window.highest
	fresh := e.window.accept(counter) // recorded even if refused below
	if !fresh {
		return dropReplay
	}
	e.used = s.tick
	if e != s.current && takesOver {
		s.current, e.refused = e, false
	}
	if e != s.current {
		if e.refused {
			return dropStale
		}
		return deliver
	}
	s.seen = now
	if newest {
		return deliverNewest
	}
	return deliver
}
