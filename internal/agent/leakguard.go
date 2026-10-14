package agent

import (
	"context"
	"net/netip"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// leakGuard is the host's leak guard (newHostGuard) with what only the
// agent knows added: the direct DNS upstreams its resolver asks, which an
// OS without socket marks (macOS's pf) must exempt by address. A change
// of upstreams is signalled on Watch, so the Enforcer applies it.
type leakGuard struct {
	routetable.Guard
	mu        sync.Mutex
	upstreams []netip.Addr
	changed   chan struct{}
}

func newLeakGuard(g routetable.Guard) *leakGuard {
	return &leakGuard{Guard: g, changed: make(chan struct{}, 1)}
}

// routeGuard is g as the route table's Guard: nil without a host guard,
// never a non-nil interface holding a nil one.
func (g *leakGuard) routeGuard() routetable.Guard {
	if g == nil || g.Guard == nil {
		return nil
	}
	return g
}

// setUpstreams records the resolver's direct upstreams.
func (g *leakGuard) setUpstreams(ups []netip.AddrPort) {
	if g == nil {
		return
	}
	addrs := make([]netip.Addr, 0, len(ups))
	for _, u := range ups {
		addrs = append(addrs, u.Addr().Unmap())
	}
	g.mu.Lock()
	g.upstreams = addrs
	g.mu.Unlock()
	select {
	case g.changed <- struct{}{}:
	default:
	}
}

func (g *leakGuard) Apply(ctx context.Context, e routetable.Exempt) error {
	g.mu.Lock()
	e.Upstreams = g.upstreams
	g.mu.Unlock()
	return g.Guard.Apply(ctx, e)
}

// Watch is the host guard's, with the upstreams' changes added.
func (g *leakGuard) Watch(ctx context.Context) (<-chan struct{}, error) {
	inner, err := g.Guard.Watch(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-inner:
				if !ok {
					return
				}
			case <-g.changed:
			}
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out, nil
}
