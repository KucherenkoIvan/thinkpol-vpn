package udp

import (
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Demux tells a shared listener whose link a datagram belongs to, so it can
// forward the datagram, untouched, to that space's worker (DESIGN.md "Server
// agent: one worker per space"). The worker runs a Listener over what it is
// forwarded, which filters replays and decrypts again.
type Demux struct {
	peers transport.Peers

	mu      sync.Mutex
	index   map[ConnID]*peerEntry
	changed <-chan struct{}
	scratch []byte
}

// NewDemux routes for the peers in peers, following its changes.
func NewDemux(peers transport.Peers) *Demux {
	return &Demux{peers: peers, scratch: make([]byte, 0, innerSize+transport.MaxPacketSize)}
}

// Route reports whose link datagram d, received by a listener, belongs to.
// The link is found by its connection id alone; the datagram's authenticator
// is then verified, so forgeries never reach a worker. Anything with ok false
// belongs to the camouflage. Route keeps no replay state: the worker's
// Listener filters replays.
func (dm *Demux) Route(d []byte) (peer transport.Identity, ok bool) {
	id, ok := connIDOf(d)
	if !ok {
		return transport.Identity{}, false
	}
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dm.index == nil {
		dm.refresh()
	} else {
		select {
		case <-dm.changed:
			dm.refresh()
		default:
		}
	}
	e := dm.index[id]
	if e == nil {
		return transport.Identity{}, false
	}
	if _, _, _, err := open(dm.scratch[:0], e.recv, d); err != nil {
		return transport.Identity{}, false
	}
	return e.link.Peer, true
}

func (dm *Demux) refresh() {
	var links []transport.PeerLink
	links, dm.changed = dm.peers.Snapshot()
	dm.index = indexPeers(links)
}
