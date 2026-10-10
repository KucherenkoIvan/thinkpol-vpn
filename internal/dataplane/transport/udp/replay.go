package udp

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
	if counter >= rejectAfterMessages {
		return false
	}
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

// senderWindows keeps a replay window for each of the last few senders seen
// on a link: a dialer that redials, or a listener that restarted, is a new
// sender with counters from zero. A replay of a sender evicted from here
// passes once more; that is acceptable for a pre-filter.
type senderWindows struct {
	tick    uint64
	entries [maxSenders]senderWindow
}

const maxSenders = 8

type senderWindow struct {
	id     senderID
	used   uint64 // tick of last use; 0 = empty
	window replayWindow
}

// accept reports whether counter is fresh for sender, and whether it is the
// newest counter seen from that sender.
func (s *senderWindows) accept(sender senderID, counter uint64) (fresh, newest bool) {
	s.tick++
	var w *senderWindow
	for i := range s.entries {
		e := &s.entries[i]
		if e.used != 0 && e.id == sender {
			w = e
			break
		}
		if w == nil || e.used < w.used {
			w = e // the least recently used, unless the sender turns up
		}
	}
	if w.used == 0 || w.id != sender {
		*w = senderWindow{id: sender}
	}
	w.used = s.tick
	newest = !w.window.started || counter > w.window.highest
	fresh = w.window.accept(counter)
	return fresh, fresh && newest
}
