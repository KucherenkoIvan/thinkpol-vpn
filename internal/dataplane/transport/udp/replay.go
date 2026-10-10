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
type senders struct {
	tick    uint64
	entries [maxSenders]senderEntry
	current *senderEntry
	seen    time.Time // last datagram accepted from current
}

const (
	maxSenders = 8
	// senderTakeover is how long the current sender must be silent before
	// an older one may take over (a dialer whose clock went back).
	senderTakeover = 30 * time.Second
)

type senderEntry struct {
	id     senderID
	used   uint64 // tick of last use; 0 = empty
	window replayWindow
}

// verdict is what a receiver does with an authenticated, fresh datagram.
type verdict int

const (
	dropReplay    verdict = iota // a counter seen before or behind the window
	dropStale                    // an unknown sender older than the current one
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
	quiet := s.current == nil || now.Sub(s.seen) > senderTakeover
	takesOver := s.current == nil || id.created() > s.current.id.created() || quiet
	if e == nil {
		if !takesOver {
			return dropStale
		}
		*victim = senderEntry{id: id}
		e = victim
	}
	newest := !e.window.started || counter > e.window.highest
	if !e.window.accept(counter) {
		return dropReplay
	}
	e.used = s.tick
	if e != s.current && takesOver {
		s.current = e
	}
	if e != s.current {
		return deliver
	}
	s.seen = now
	if newest {
		return deliverNewest
	}
	return deliver
}
