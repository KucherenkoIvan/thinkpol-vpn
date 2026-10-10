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
