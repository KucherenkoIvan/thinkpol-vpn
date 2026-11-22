package reality

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"
)

// checkBackoffMin and checkBackoffMax bound how long a listener waits
// before checking again a target whose last check failed: the first wait
// is up to checkBackoffMin, each later one doubles, up to checkBackoffMax,
// and each is drawn at random from its upper half. The agent retries a
// failed listener every few seconds (agent.RetryAfter); unbacked, each
// retry would dial the target on that fixed period, from the server's
// address, for as long as the check fails. checkBackoffMax is how late a
// server serves once its target is reachable again (one that started
// before its uplink, say), and about how often a target that stays down is
// dialled: the package doc's trade-off.
var (
	checkBackoffMin = 10 * time.Second
	checkBackoffMax = 2 * time.Minute
)

// targetChecks gates a transport's checks of its targets (verifyTarget,
// then detect): a target whose last check failed isn't dialled again
// before its wait ends, and Listen fails meanwhile with the last check's
// error. A check that passed leaves nothing behind: a listener that
// opened is kept across the agent's retries, so it isn't checked again
// until the map changes it.
type targetChecks struct {
	mu     sync.Mutex
	now    func() time.Time // the real clock; tests replace it
	failed map[string]*failedCheck
}

type failedCheck struct {
	n    int // consecutive failures
	next time.Time
	err  error
}

func newTargetChecks() *targetChecks {
	return &targetChecks{now: time.Now, failed: map[string]*failedCheck{}}
}

// run runs check for the target dest with names, unless dest's last check
// failed and its wait hasn't ended. A check that failed because ctx ended
// isn't counted: it didn't learn anything about the target.
func (c *targetChecks) run(ctx context.Context, dest string, names map[string]bool, check func() error) error {
	key := checkKey(dest, names)
	c.mu.Lock()
	if f := c.failed[key]; f != nil {
		if wait := f.next.Sub(c.now()); wait > 0 {
			c.mu.Unlock()
			return fmt.Errorf("reality: target %s: not checked again for %s after its check failed: %w", dest, wait.Round(time.Second), f.err)
		}
	}
	c.mu.Unlock()
	err := check()
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		delete(c.failed, key)
	case ctx.Err() != nil:
	default:
		f := c.failed[key]
		if f == nil {
			f = &failedCheck{}
			c.failed[key] = f
		}
		f.n++
		f.err = err
		f.next = c.now().Add(checkBackoff(f.n))
	}
	return err
}

// checkBackoff is the wait after the nth failed check in a row.
func checkBackoff(n int) time.Duration {
	d := checkBackoffMin
	for i := 1; i < n && d < checkBackoffMax; i++ {
		d *= 2
	}
	d = min(d, checkBackoffMax)
	return d/2 + rand.N(d/2+1)
}

func checkKey(dest string, names map[string]bool) string {
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	slices.Sort(sorted)
	return dest + " " + strings.Join(sorted, ",")
}
