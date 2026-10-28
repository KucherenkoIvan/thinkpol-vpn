package localapi

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// How a membership lookup is bounded, and how long its answer is kept: a
// user removed from the group keeps control for at most
// membershipCacheTTL.
const (
	membershipTimeout  = 3 * time.Second
	membershipCacheTTL = 10 * time.Second
	membershipCacheMax = 64
)

// cachedMembership is a [Membership] that asks lookup, one lookup at a
// time and each bounded by timeout, and keeps each answer for ttl. A
// failed lookup is not kept, and is not a member.
type cachedMembership struct {
	lookup  func(ctx context.Context, uid, gid uint32) (bool, error)
	timeout time.Duration
	ttl     time.Duration
	now     func() time.Time

	// one holds the right to look up: a caller waiting for it finds
	// the answer the one before it got.
	one     chan struct{}
	mu      sync.Mutex
	answers map[membershipKey]membershipAnswer
}

type membershipKey struct{ uid, gid uint32 }

type membershipAnswer struct {
	member bool
	until  time.Time
}

func newCachedMembership(lookup func(ctx context.Context, uid, gid uint32) (bool, error)) *cachedMembership {
	return &cachedMembership{
		lookup:  lookup,
		timeout: membershipTimeout,
		ttl:     membershipCacheTTL,
		now:     time.Now,
		one:     make(chan struct{}, 1),
		answers: map[membershipKey]membershipAnswer{},
	}
}

func (m *cachedMembership) IsMember(ctx context.Context, uid, gid uint32) (bool, error) {
	k := membershipKey{uid, gid}
	if member, ok := m.cached(k); ok {
		return member, nil
	}
	select {
	case m.one <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-m.one }()
	if member, ok := m.cached(k); ok {
		return member, nil
	}
	lctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	member, err := m.lookup(lctx, uid, gid)
	if err == nil {
		// A lookup that ignored its deadline doesn't count.
		err = lctx.Err()
	}
	if err != nil {
		return false, fmt.Errorf("membership of uid %d in group %d: %w", uid, gid, err)
	}
	m.keep(k, member)
	return member, nil
}

func (m *cachedMembership) cached(k membershipKey) (member, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.answers[k]
	if !ok || !m.now().Before(a.until) {
		return false, false
	}
	return a.member, true
}

func (m *cachedMembership) keep(k membershipKey, member bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if len(m.answers) >= membershipCacheMax {
		for k, a := range m.answers {
			if !now.Before(a.until) {
				delete(m.answers, k)
			}
		}
		if len(m.answers) >= membershipCacheMax {
			clear(m.answers)
		}
	}
	m.answers[k] = membershipAnswer{member: member, until: now.Add(m.ttl)}
}
