package reality

import (
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// maxRemembered bounds one space's replay cache: a hello that would
	// grow it past that goes to the camouflage, like any other it can't
	// vouch for. Only authenticated hellos enter it, so filling it takes
	// at least maxRemembered/replayShare of the space's own credentials,
	// and refuses only that space's hellos.
	maxRemembered = 1 << 16
	// replayShare is the most one short id has remembered at once: a
	// credential that dials faster than that fills its own share of its
	// space's cache only. A legitimate dialer needs a few per window.
	replayShare = 1 << 10
)

// replays is a replay cache per space, so one space's hellos, however
// many credentials its map lists, neither fill another space's cache nor
// tell anything of its traffic.
type replays struct {
	window  time.Duration
	mu      sync.Mutex
	bySpace map[transport.SpaceID]*replayCache
}

func newReplays(window time.Duration) *replays {
	return &replays{window: window, bySpace: map[transport.SpaceID]*replayCache{}}
}

// admit is replayCache.admit in space's cache, under that cache's lock
// only: one space's full scan doesn't hold up another's hellos. A cache
// prune dropped between the lookup and the admit is dead, and the hello
// is admitted into the space's next one, never into a cache nothing reads
// (where it would be free to replay once if the space came back).
func (r *replays) admit(space transport.SpaceID, id shortID, sessionID []byte, sent uint32, now time.Time) bool {
	for {
		r.mu.Lock()
		c := r.bySpace[space]
		if c == nil {
			c = newReplayCache(r.window)
			r.bySpace[space] = c
		}
		r.mu.Unlock()
		if admitted, live := c.admit(id, sessionID, sent, now); live {
			return admitted
		}
	}
}

// prune drops the caches of spaces not in keep once all they remember
// left the window: until then a space that comes back still has them.
func (r *replays) prune(keep map[transport.SpaceID]bool, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for space, c := range r.bySpace {
		if !keep[space] && c.retire(now) {
			delete(r.bySpace, space)
		}
	}
}

// replayCache remembers the sealed session ids of one space's
// authenticated hellos, per short id, while they could still be fresh,
// so each is admitted once. An entry is forgotten once its own sealed time leaves the window,
// whatever else is remembered (a hello sealed ahead of the clock holds
// only itself).
type replayCache struct {
	mu     sync.Mutex
	window time.Duration
	byID   map[shortID]map[[sessionIDSize]byte]uint32 // sealed time by session id
	total  int
	dead   bool // retired: dropped by prune, admitting nothing
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{window: window, byID: map[shortID]map[[sessionIDSize]byte]uint32{}}
}

// admit reports whether a hello from id whose session id is sessionID,
// sealed at sent, is fresh and new, and remembers it if so; live is false
// on a cache prune retired, which admits nothing.
func (c *replayCache) admit(id shortID, sessionID []byte, sent uint32, now time.Time) (admitted, live bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return false, false
	}
	return c.admitLocked(id, sessionID, sent, now), true
}

// admitLocked is admit, c.mu held.
func (c *replayCache) admitLocked(id shortID, sessionID []byte, sent uint32, now time.Time) bool {
	if !transport.FreshWithin(sent, now, c.window) {
		return false
	}
	var sid [sessionIDSize]byte
	copy(sid[:], sessionID)
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
		// A scan of the space's whole cache under its lock: reaching it
		// takes maxRemembered/replayShare (64) of the space's credentials
		// filling their shares.
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

// retire forgets every entry that left the window and, if that left the
// cache empty, retires it for good and reports true.
func (c *replayCache) retire(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.byID {
		c.forget(id, now)
	}
	c.dead = c.total == 0
	return c.dead
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
