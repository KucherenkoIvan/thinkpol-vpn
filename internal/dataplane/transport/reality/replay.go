package reality

import (
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// maxRemembered bounds the replay cache: a hello that would grow it
	// past that goes to the camouflage, like any other it can't vouch for.
	// Only authenticated hellos enter it, so filling it takes credentials:
	// at least maxRemembered/replayShare of them.
	maxRemembered = 1 << 16
	// replayShare is the most one short id has remembered at once: a
	// credential that dials faster than that fills its own share only.
	// A legitimate dialer needs a few per window.
	replayShare = 1 << 10
)

// replayCache remembers the sealed session ids of authenticated hellos,
// per short id, while they could still be fresh, so each is admitted once.
// An entry is forgotten once its own sealed time leaves the window,
// whatever else is remembered (a hello sealed ahead of the clock holds
// only itself).
type replayCache struct {
	mu     sync.Mutex
	window time.Duration
	byID   map[shortID]map[[sessionIDSize]byte]uint32 // sealed time by session id
	total  int
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{window: window, byID: map[shortID]map[[sessionIDSize]byte]uint32{}}
}

// admit reports whether a hello from id whose session id is sessionID,
// sealed at sent, is fresh and new, and remembers it if so.
func (c *replayCache) admit(id shortID, sessionID []byte, sent uint32, now time.Time) bool {
	if !transport.FreshWithin(sent, now, c.window) {
		return false
	}
	var sid [sessionIDSize]byte
	copy(sid[:], sessionID)
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := c.byID[id]
	if _, ok := seen[sid]; ok {
		return false
	}
	if len(seen) >= replayShare {
		if c.forget(id, now); len(c.byID[id]) >= replayShare {
			return false
		}
	}
	if c.total >= maxRemembered {
		for other := range c.byID {
			c.forget(other, now)
		}
		if c.total >= maxRemembered {
			return false
		}
	}
	seen = c.byID[id] // forget may have dropped it
	if seen == nil {
		seen = map[[sessionIDSize]byte]uint32{}
		c.byID[id] = seen
	}
	seen[sid] = sent
	c.total++
	return true
}

// forget drops id's entries that left the window.
func (c *replayCache) forget(id shortID, now time.Time) {
	seen := c.byID[id]
	for sid, sent := range seen {
		if !transport.FreshWithin(sent, now, c.window) {
			delete(seen, sid)
			c.total--
		}
	}
	if len(seen) == 0 {
		delete(c.byID, id)
	}
}
