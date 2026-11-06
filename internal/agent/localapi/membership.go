package localapi

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// How long a Directory Services query may take (a membership lookup, or
// finding the group's gid), and how long a membership answer is kept: a
// user removed from the group whose session never carried it loses control
// within membershipCacheTTL. A failure is kept briefly too, so that while
// Directory Services is down each caller is refused at once rather than
// after its own timeout: longer than dsTimeout, so that during an outage a
// steady poller is refused at once more often than it waits, and shorter
// than an answer. At most membershipCacheMax answers are kept.
const (
	dsTimeout            = 3 * time.Second
	membershipCacheTTL   = 10 * time.Second
	membershipFailureTTL = 5 * time.Second
	membershipCacheMax   = 64
)

// cachedMembership is a [Membership] that asks inner, one lookup at a time
// and each bounded by timeout whoever waits for it, and keeps each answer
// for ttl and each failure (an error, a timeout) for failureTTL; a failure
// is not a member. A caller that leaves stops waiting; its lookup runs on
// and is kept. Past membershipCacheMax answers, the expired ones are
// dropped, then all.
type cachedMembership struct {
	inner      Membership
	timeout    time.Duration
	ttl        time.Duration
	failureTTL time.Duration
	now        func() time.Time

	// lookupSlot is the right to ask inner, held until the lookup ends: a
	// caller that waited for it finds the answer the one before it got.
	lookupSlot chan struct{}
	mu         sync.Mutex
	answers    map[membershipKey]membershipAnswer
}

type membershipKey struct{ uid, gid uint32 }

type membershipAnswer struct {
	member bool
	err    error
	until  time.Time
}

func newCachedMembership(inner Membership) *cachedMembership {
	return &cachedMembership{
		inner:      inner,
		timeout:    dsTimeout,
		ttl:        membershipCacheTTL,
		failureTTL: membershipFailureTTL,
		now:        time.Now,
		lookupSlot: make(chan struct{}, 1),
		answers:    map[membershipKey]membershipAnswer{},
	}
}

func (m *cachedMembership) IsMember(ctx context.Context, uid, gid uint32) (bool, error) {
	k := membershipKey{uid, gid}
	if a, ok := m.cached(k); ok {
		return a.member, a.err
	}
	select {
	case m.lookupSlot <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if a, ok := m.cached(k); ok {
		<-m.lookupSlot
		return a.member, a.err
	}
	done := make(chan membershipAnswer, 1)
	go func() {
		defer func() { <-m.lookupSlot }()
		done <- m.lookup(k)
	}()
	select {
	case a := <-done:
		return a.member, a.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// lookup asks inner about k, bounded by timeout, and keeps the answer.
// What Directory Services says doesn't depend on who asked, so the lookup
// doesn't end with its caller. inner must not panic: lookup runs on its
// own goroutine, which grpckit's panic recovery doesn't cover.
func (m *cachedMembership) lookup(k membershipKey) membershipAnswer {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	member, err := m.inner.IsMember(ctx, k.uid, k.gid)
	if ctx.Err() != nil {
		// Past the deadline, even an answer doesn't count.
		member, err = false, fmt.Errorf("no answer within %v: %w", m.timeout, ctx.Err())
	}
	a := membershipAnswer{member: member, until: m.now().Add(m.ttl)}
	if err != nil {
		a = membershipAnswer{err: err, until: m.now().Add(m.failureTTL)}
	}
	m.keep(k, a)
	return a
}

func (m *cachedMembership) cached(k membershipKey) (membershipAnswer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.answers[k]
	if !ok || !m.now().Before(a.until) {
		return membershipAnswer{}, false
	}
	return a, true
}

func (m *cachedMembership) keep(k membershipKey, a membershipAnswer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.answers) >= membershipCacheMax {
		now := m.now()
		for old, oa := range m.answers {
			if !now.Before(oa.until) {
				delete(m.answers, old)
			}
		}
		if len(m.answers) >= membershipCacheMax {
			clear(m.answers)
		}
	}
	m.answers[k] = a
}
