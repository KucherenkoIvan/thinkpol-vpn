package udp

import (
	"crypto/cipher"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Demux tells a shared listener whose link a datagram belongs to, so it can
// forward the datagram, untouched, to that space's worker (DESIGN.md "Server
// agent: one worker per space"). The worker runs a Listener over what it is
// forwarded, which checks for replays and decrypts.
type Demux struct {
	peers transport.Peers

	mu       sync.Mutex
	index    map[ConnID]*peerEntry
	changed  <-chan struct{}
	sessions map[ConnID]demuxSession
	scratch  []byte
}

// demuxSession caches the key of the latest session seen per credential, so
// only a new session costs a key derivation.
type demuxSession struct {
	sess session
	recv cipher.AEAD
}

// NewDemux routes for the peers in peers, following its changes.
func NewDemux(peers transport.Peers) *Demux {
	return &Demux{peers: peers, scratch: make([]byte, 0, maxDatagram)}
}

// Route reports whose link datagram d, received by a listener, belongs to.
// The link is found by its connection id alone; the datagram's authenticator
// is then verified, so forgeries never reach a worker. Anything with ok false
// belongs to the camouflage. Route keeps no replay state: the worker's
// Listener drops replays.
func (dm *Demux) Route(d []byte) (peer transport.Identity, ok bool) {
	h, ok := parseHeader(d)
	if !ok {
		return transport.Identity{}, false
	}
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.refresh()
	e := dm.index[h.id]
	if e == nil {
		return transport.Identity{}, false
	}
	s, cached := dm.sessions[h.id]
	if !cached || s.sess != h.sess {
		s = demuxSession{sess: h.sess, recv: e.aead(h.sess, toListener)}
	}
	if _, err := open(dm.scratch[:0], s.recv, h, d); err != nil {
		return transport.Identity{}, false
	}
	dm.sessions[h.id] = s // only authenticated sessions displace the cache
	return e.link.Peer, true
}

func (dm *Demux) refresh() {
	if dm.index != nil {
		select {
		case <-dm.changed:
		default:
			return
		}
	}
	var links []transport.PeerLink
	links, dm.changed = dm.peers.Snapshot()
	index := indexPeers(links)
	sessions := make(map[ConnID]demuxSession, len(index))
	for id, e := range index {
		if s, ok := dm.sessions[id]; ok && e.sameAs(dm.index[id]) {
			sessions[id] = s
		}
	}
	dm.index, dm.sessions = index, sessions
}
