package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Inbound is where a data plane's listeners come from: the node's own
// sockets on a device (DirectInbound), the supervisor's shared listeners
// in a server's worker (SharedInbound). RunDataPlane serves whatever it
// lists, the same way in both modes.
type Inbound interface {
	// Listeners are the listeners to serve with the node's section s.
	Listeners(s netmap.Section) []Listener
	// Changed is signalled when Listeners would list something else for
	// the same section; nil when only the section changes them.
	Changed() <-chan struct{}
}

// Listener is one listener a data plane serves.
type Listener struct {
	// Key identifies the listener: one with the same key keeps running
	// across changes, one whose key went is closed.
	Key       string
	Transport string
	// Open opens it, accepting peers (the engine's table for Transport).
	Open func(ctx context.Context, peers transport.Peers) (transport.Listener, error)
	// Done, if not nil, is closed once the listener is gone for good: it
	// is never opened again.
	Done <-chan struct{}
}

// DirectInbound opens the listeners the node's section names on the node's
// own sockets: a device, or a server run in device mode.
func DirectInbound(reg *transport.Registry) Inbound { return directInbound{reg} }

type directInbound struct{ reg *transport.Registry }

func (d directInbound) Listeners(s netmap.Section) []Listener {
	out := make([]Listener, 0, len(s.Node.Listeners))
	for _, l := range s.Node.Listeners {
		cfg := transport.ListenConfig{Address: l.Address.String(), Settings: l.Settings}
		out = append(out, Listener{
			Key:       l.Transport + " " + cfg.Address + " " + hex.EncodeToString(l.Settings),
			Transport: l.Transport,
			Open: func(ctx context.Context, peers transport.Peers) (transport.Listener, error) {
				t, ok := d.reg.Get(l.Transport)
				if !ok {
					return nil, fmt.Errorf("unknown transport %q", l.Transport)
				}
				return t.Listen(ctx, cfg, transport.Accept{Peers: peers})
			},
		})
	}
	return out
}

func (directInbound) Changed() <-chan struct{} { return nil }

// SharedInbound serves the supervisor's shared listeners a worker is given
// (worker.Session.Listeners), whatever its section says: only the node
// owner's listeners are opened, by the supervisor.
func SharedInbound(ctx context.Context, reg *transport.Registry, updates <-chan []worker.SharedListener) Inbound {
	s := &sharedInbound{reg: reg, changed: make(chan struct{}, 1)}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ls, ok := <-updates:
				if !ok {
					return
				}
				s.mu.Lock()
				s.current = ls
				s.mu.Unlock()
				select {
				case s.changed <- struct{}{}:
				default:
				}
			}
		}
	}()
	return s
}

type sharedInbound struct {
	reg     *transport.Registry
	changed chan struct{}

	mu      sync.Mutex
	current []worker.SharedListener
}

func (s *sharedInbound) Listeners(netmap.Section) []Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Listener, 0, len(s.current))
	for _, l := range s.current {
		out = append(out, Listener{
			Key:       "shared " + strconv.FormatUint(uint64(l.ID), 10),
			Transport: l.Transport,
			Open: func(_ context.Context, peers transport.Peers) (transport.Listener, error) {
				return l.Listen(s.reg, transport.Accept{Peers: peers})
			},
			Done: l.Done,
		})
	}
	return out
}

func (s *sharedInbound) Changed() <-chan struct{} { return s.changed }
