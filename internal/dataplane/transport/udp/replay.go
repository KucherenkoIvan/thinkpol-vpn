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
// datagrams stay fresh (maxClockSkew): in a slot, with the counters seen,
// even when it was refused; or, once evicted from the slots, by id alone,
// refused outright. So a replay can't come back later as a "new" sender
// once the current one goes quiet.
type senders struct {
	tick    uint64
	entries [maxSenders]senderEntry
	current *senderEntry
	seen    time.Time              // last datagram accepted from current
	evicted map[senderID]time.Time // when; refused for maxClockSkew
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
		if s.wasEvicted(id, now) {
			return dropStale
		}
		if victim.used != 0 {
			s.remember(victim.id, now)
		}
		*victim = senderEntry{id: id, refused: true}
		e = victim
	}
	quiet := s.current == nil || now.Sub(s.seen) > senderTakeover
	takesOver := s.current == nil || id.created() > s.current.id.created() || quiet
	newest := !e.window.started || counter > e.window.highest
	fresh := e.window.accept(counter) // recorded even if refused below
	e.used = s.tick
	if !fresh {
		return dropReplay
	}
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

func (s *senders) wasEvicted(id senderID, now time.Time) bool {
	at, ok := s.evicted[id]
	if ok && now.Sub(at) > maxClockSkew {
		delete(s.evicted, id)
		return false
	}
	return ok
}

func (s *senders) remember(id senderID, now time.Time) {
	if s.evicted == nil {
		s.evicted = make(map[senderID]time.Time)
	}
	for old, at := range s.evicted {
		if now.Sub(at) > maxClockSkew {
			delete(s.evicted, old)
		}
	}
	s.evicted[id] = now
}
