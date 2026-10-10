package transport

import (
	"fmt"
	"slices"
	"sync"
)

// PeerLink is what the map gives the listening end of one link: who may
// dial, how to check them, and the link's settings.
type PeerLink struct {
	Peer Identity
	// Verifier is what the listener checks the dialer's credential against:
	// for a symmetric transport, the shared secret itself.
	Verifier []byte
	// Settings is the transport's own settings message for the link.
	Settings []byte
	// Shaping is how the listening end shapes what it sends on this link.
	Shaping Shaping
}

// PeerError is a peer link a listener couldn't use, and why.
type PeerError struct {
	Peer Identity
	Err  error
}

func (e PeerError) Error() string { return fmt.Sprintf("peer %s: %v", e.Peer, e.Err) }

func (e PeerError) Unwrap() error { return e.Err }

// Peers is a listener's table of the links it accepts. It changes when a new
// map arrives. A supervisor serving several spaces merges their tables into
// one, stamping each link's Space from the map it came from, never from the
// map's contents.
type Peers interface {
	// Snapshot returns the links accepted right now, and a channel closed
	// once that changes. Callers must not modify the returned slice.
	Snapshot() ([]PeerLink, <-chan struct{})
}

// PeerTable is a Peers that is replaced as a whole.
type PeerTable struct {
	mu      sync.Mutex
	links   []PeerLink
	changed chan struct{}
}

// NewPeerTable returns a table holding links.
func NewPeerTable(links ...PeerLink) *PeerTable {
	return &PeerTable{links: slices.Clone(links), changed: make(chan struct{})}
}

// Set replaces the table and wakes everyone watching it.
func (t *PeerTable) Set(links []PeerLink) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.links = slices.Clone(links)
	close(t.changed)
	t.changed = make(chan struct{})
}

// Snapshot implements Peers.
func (t *PeerTable) Snapshot() ([]PeerLink, <-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.links, t.changed
}
