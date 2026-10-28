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
// after its own timeout. At most membershipCacheMax answers are kept.
const (
	dsTimeout            = 3 * time.Second
	membershipCacheTTL   = 10 * time.Second
	membershipFailureTTL = 2 * time.Second
	membershipCacheMax   = 64
)

// cachedMembership is a [Membership] that asks inner, one lookup at a time
// and each bounded by timeout, and keeps each answer for ttl and each
// failure (an error, a timeout) for failureTTL; a failure is not a member.
// A lookup abandoned because its caller left isn't kept. Past
// membershipCacheMax answers, the expired ones are dropped, then all.
type cachedMembership struct {
	inner      Membership
	timeout    time.Duration
	ttl        time.Duration
	failureTTL time.Duration
	now        func() time.Time

	// lookupSlot is the right to ask inner: a caller that waited for it
	// finds the answer the one before it got.
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
	defer func() { <-m.lookupSlot }()
	if a, ok := m.cached(k); ok {
		return a.member, a.err
	}
	lctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	member, err := m.inner.IsMember(lctx, uid, gid)
	if ctx.Err() != nil {
		// The caller left: its lookup says nothing about the next one.
		return false, ctx.Err()
	}
	if lctx.Err() != nil {
		// Past the deadline, even an answer doesn't count.
		member, err = false, fmt.Errorf("no answer within %v: %w", m.timeout, lctx.Err())
	}
	if err != nil {
		m.keep(k, membershipAnswer{err: err, until: m.now().Add(m.failureTTL)})
		return false, err
	}
	m.keep(k, membershipAnswer{member: member, until: m.now().Add(m.ttl)})
	return member, nil
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
