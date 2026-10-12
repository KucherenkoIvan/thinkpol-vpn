package worker

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// ErrUnsupported is returned by Run where there are no workers: they need
// Linux namespaces.
var ErrUnsupported = errors.New("worker: needs Linux")

// Session is what a sandboxed worker knows about its space and namespace.
type Session struct {
	Space netmap.SpaceID
	// Interface is the namespace's end of the veth pair to the root
	// namespace, up with Addrs and default routes via Gateways (one per
	// family). Egress and outgoing links leave through it.
	Interface string
	Addrs     []netip.Prefix
	Gateways  []netip.Addr
	// Config delivers the space's opaque configuration from the supervisor:
	// the current one first, then each change, latest-wins (an older pending
	// one is dropped).
	Config <-chan []byte
	// Listeners delivers the supervisor's shared listeners the worker is
	// served by: the current set first, then each change, latest-wins. A
	// listener keeps its SharedListener (and its Packets or Streams) for as
	// long as it is listed.
	Listeners <-chan []SharedListener
	// SharedDrops reports what the worker dropped of what the shared
	// listeners forwarded.
	SharedDrops func() SharedDrops
	// SharedCounters delivers, every few seconds, what the supervisor's
	// shared listeners did for this space (latest-wins), for the worker's
	// sealed telemetry. Only the space's own figures.
	SharedCounters <-chan ipc.SharedCounters
	// Seeds are the space's blob seeds the supervisor sent, each in place
	// before the config whose map names it is delivered.
	Seeds *Seeds
}

// Seeds hold blob seeds by the SHA-256 of their content; the data plane
// checks them against its map before use.
type Seeds struct {
	mu sync.Mutex
	m  map[[32]byte][]byte
}

// NewSeeds holds none.
func NewSeeds() *Seeds { return &Seeds{m: map[[32]byte][]byte{}} }

// Add holds b.
func (s *Seeds) Add(b []byte) {
	s.mu.Lock()
	s.m[sha256.Sum256(b)] = b
	s.mu.Unlock()
}

// Get returns the seed with this SHA-256, nil if none.
func (s *Seeds) Get(sha [32]byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[sha]
}

// Retain drops every seed keep refuses.
func (s *Seeds) Retain(keep func(sha [32]byte) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sha := range s.m {
		if !keep(sha) {
			delete(s.m, sha)
		}
	}
}

// Hashes lists the seeds held.
func (s *Seeds) Hashes() [][32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][32]byte, 0, len(s.m))
	for sha := range s.m {
		out = append(out, sha)
	}
	return out
}

// Serve runs a space's data plane until ctx ends. Returning early, with or
// without an error, ends the worker, and the supervisor restarts it.
type Serve func(ctx context.Context, s Session) error

// Idle serves nothing until ctx ends: a worker for tests of the sandbox and
// the supervisor. `thinkpol worker` serves agent.ServeSpace.
func Idle(ctx context.Context, _ Session) error {
	<-ctx.Done()
	return nil
}
