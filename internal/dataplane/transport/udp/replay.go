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
// Every sender that ever showed up is remembered for as long as a
// datagram of it could still be fresh: in a slot, with the counters seen,
// even when it was refused; or, once evicted from the slots, by id alone
// with the newest sealed send time seen from it (freshness is what bounds
// a replay, and it runs on the sender's sealed time — a receiver whose
// wall clock steps back stays consistent with it), refused outright. So a
// replay can't come back later as a "new" sender once the current one
// goes quiet. The evicted are at most maxEvicted, the oldest forgotten
// first: a dialer churning through senders can't make this grow, or cost
// more per datagram, without bound. A forgotten sender is older than the
// churning current one, so while that one is active it is still refused;
// the residual: a sender evicted from the slots and then pushed out of
// the ring by more than maxEvicted further evictions while its datagrams
// could still be fresh can take over again once the current sender has
// been silent for senderTakeover (30 s), and making those evictions
// requires the credential.
type senders struct {
	tick    uint64
	entries [maxSenders]senderEntry
	current *senderEntry
	seen    time.Time // last datagram accepted from current
	newest  uint32    // newest sealed send time any datagram has shown
	evicted evictedSenders
}

// evictedSenders are the ids of senders evicted from the slots, refused
// while a datagram of them could still be fresh: a map for lookups and a
// ring in eviction order, so expiry and the bound cost O(1) per eviction.
type evictedSenders struct {
	byID       map[senderID]*evictedSender
	ring       []evictedSender
	head, size int
}

type evictedSender struct {
	id   senderID
	sent uint32 // the newest sealed send time seen from it
}

// maxEvicted bounds a credential's evicted senders.
const maxEvicted = 1024

func (e *evictedSenders) add(id senderID, sent uint32, now time.Time) {
	e.expire(now)
	if s, ok := e.byID[id]; ok { // never seen, but stay honest
		s.note(sent)
		return
	}
	if e.ring == nil {
		e.byID = make(map[senderID]*evictedSender)
		e.ring = make([]evictedSender, maxEvicted)
	}
	if e.size == len(e.ring) {
		e.pop()
	}
	s := &e.ring[(e.head+e.size)%len(e.ring)]
	*s = evictedSender{id: id, sent: sent}
	e.size++
	e.byID[id] = s
}

func (e *evictedSenders) pop() {
	old := &e.ring[e.head]
	if cur, ok := e.byID[old.id]; ok && cur == old {
		delete(e.byID, old.id)
	}
	e.head = (e.head + 1) % len(e.ring)
	e.size--
}

func (e *evictedSenders) expire(now time.Time) {
	// The ring is in eviction order, not send-time order, so a stale
	// entry behind a fresh head lingers until the head ages past it: at
	// most maxEvicted entries, each forgotten once no datagram sealed at
	// its newest send time could still be fresh.
	for e.size > 0 && !sentFresh(e.ring[e.head].sent, now) {
		e.pop()
	}
}

// seen reports whether an evicted sender is still remembered, noting the
// newest sealed send time seen from it: a sender the receiver keeps
// turning away keeps sending, and its newest datagrams must be remembered
// as long as they are fresh, not from its eviction alone.
func (e *evictedSenders) seen(id senderID, sent uint32) bool {
	s, ok := e.byID[id]
	if !ok {
		return false
	}
	s.note(sent)
	return true
}

func (s *evictedSender) note(sent uint32) {
	if later(sent, s.sent) {
		s.sent = sent
	}
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
	sent    uint32 // the newest sealed send time seen from it
	window  replayWindow
}

// verdict is what the receive ladder did with a datagram: the two
// failures before the sender rules, then what the sender rules say.
type verdict int

const (
	dropUnauthenticated verdict = iota // open failed: not under the credential's key
	dropStaleTimestamp                 // sealed too far from the receiver's clock, or before it started
	dropReplay                         // a counter seen before or behind the window
	dropStale                          // a sender older than the current one, or forgotten
	deliver                            // deliver, but don't move the reply address
	deliverNewest                      // deliver; the current sender's newest counter
)

func (s *senders) admit(id senderID, counter uint64, sent uint32, now time.Time) verdict {
	s.tick++
	if later(sent, s.newest) {
		s.newest = sent
	}
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
		if s.evicted.seen(id, sent) {
			return dropStale
		}
		if victim.used != 0 {
			s.evicted.add(victim.id, victim.sent, now)
		}
		*victim = senderEntry{id: id, refused: true, sent: sent}
		e = victim
	}
	if later(sent, e.sent) {
		e.sent = sent
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
