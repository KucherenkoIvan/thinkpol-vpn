package reality

import (
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// maxRemembered bounds the replay cache: a hello that would grow it past
// that goes to the camouflage, like any other it can't vouch for. Only
// authenticated hellos enter it, so filling it takes a credential.
const maxRemembered = 1 << 16

// replayCache remembers the sealed session ids of authenticated hellos
// while they could still be fresh, so each is admitted once. An entry
// expires once its sealed time leaves the window; entries go in the order
// they arrived, so one sealed earlier than the entry before it waits for
// that one (remembered longer, never shorter).
type replayCache struct {
	mu     sync.Mutex
	seen   map[[sessionIDSize]byte]struct{}
	queue  []remembered
	window time.Duration
}

type remembered struct {
	id   [sessionIDSize]byte
	sent uint32
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{seen: make(map[[sessionIDSize]byte]struct{}), window: window}
}

// admit reports whether a hello whose session id is sessionID, sealed at
// sent, is fresh and new, and remembers it if so.
func (c *replayCache) admit(sessionID []byte, sent uint32, now time.Time) bool {
	if !transport.FreshWithin(sent, now, c.window) {
		return false
	}
	var id [sessionIDSize]byte
	copy(id[:], sessionID)
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.queue) > 0 && !transport.FreshWithin(c.queue[0].sent, now, c.window) {
		delete(c.seen, c.queue[0].id)
		c.queue = c.queue[1:]
	}
	if _, ok := c.seen[id]; ok || len(c.queue) >= maxRemembered {
		return false
	}
	c.seen[id] = struct{}{}
	c.queue = append(c.queue, remembered{id: id, sent: sent})
	return true
}
