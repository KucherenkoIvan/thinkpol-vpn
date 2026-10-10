package transport

import (
	"slices"
	"sync"
)

// PeerLink is one link a listener accepts: who the peer is and the link's
// settings from the map.
type PeerLink struct {
	Peer   Identity
	Config LinkConfig
}

// Peers is a listener's table of the links it accepts. It changes when a new
// map arrives; a supervisor serving several spaces can merge their tables
// into one, since Identity carries the space.
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
