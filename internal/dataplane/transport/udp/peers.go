package udp

import (
	"crypto/cipher"
	"errors"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// peerEntry is one usable inbound credential, with its keys derived once.
type peerEntry struct {
	link transport.PeerLink
	recv cipher.AEAD
	send cipher.AEAD
	out  *rotatingID // listener to dialer
}

func newPeerEntry(pl transport.PeerLink) *peerEntry {
	return &peerEntry{
		link: pl,
		recv: newAEAD(pl.Verifier, toListener),
		send: newAEAD(pl.Verifier, toDialer),
		out:  &rotatingID{secret: pl.Verifier, dir: toDialer},
	}
}

var (
	errDuplicateSecret = errors.New("udp: another peer link has the same secret")
	errConnIDCollision = errors.New("udp: connection id collides with another peer link's")
)

// peerSet is a peer table indexed for receiving: entries by secret, and by
// the connection ids of the epochs around the current one.
type peerSet struct {
	bySecret map[string]*peerEntry
	epoch    int64
	byID     map[connID]*peerEntry
	rejected []transport.PeerError // by indexPeers
	refused  map[string]refusal    // by secret: links checkInbound refused
	collided []transport.PeerError // by the latest reindex
}

// refusal is a peer link the table holds but udp can't use as it says.
type refusal struct {
	peer transport.Identity
	err  error
}

func (ps *peerSet) problems() []transport.PeerError {
	return append(append([]transport.PeerError(nil), ps.rejected...), ps.collided...)
}

// indexPeers checks every link, and drops (and reports) both links of a
// duplicate secret rather than guessing which one is meant.
func indexPeers(links []transport.PeerLink, epoch int64) *peerSet {
	ps := &peerSet{bySecret: make(map[string]*peerEntry, len(links)), refused: map[string]refusal{}}
	dup := map[string]bool{}
	for _, pl := range links {
		if err := checkInbound(pl); err != nil {
			ps.rejected = append(ps.rejected, transport.PeerError{Peer: pl.Peer, Err: err})
			ps.refused[string(pl.Verifier)] = refusal{pl.Peer, err}
			continue
		}
		key := string(pl.Verifier)
		if prev, ok := ps.bySecret[key]; ok || dup[key] {
			if ok {
				ps.rejected = append(ps.rejected, transport.PeerError{Peer: prev.link.Peer, Err: errDuplicateSecret})
				delete(ps.bySecret, key)
				dup[key] = true
			}
			ps.rejected = append(ps.rejected, transport.PeerError{Peer: pl.Peer, Err: errDuplicateSecret})
			continue
		}
		ps.bySecret[key] = newPeerEntry(pl)
	}
	ps.reindex(epoch)
	return ps
}

// reindex derives the connection ids for epoch and its neighbours. Should
// two secrets ever derive the same id, both lose it.
func (ps *peerSet) reindex(epoch int64) {
	ps.epoch = epoch
	ps.byID = make(map[connID]*peerEntry, 3*len(ps.bySecret))
	ps.collided = nil
	collided := map[connID]bool{}
	for _, e := range ps.bySecret {
		for ep := epoch - 1; ep <= epoch+1; ep++ {
			id := connIDFor(e.link.Verifier, toListener, ep)
			if other, ok := ps.byID[id]; (ok && other != e) || collided[id] {
				if ok {
					ps.collided = append(ps.collided, transport.PeerError{Peer: other.link.Peer, Err: errConnIDCollision})
				}
				collided[id] = true
				delete(ps.byID, id)
				ps.collided = append(ps.collided, transport.PeerError{Peer: e.link.Peer, Err: errConnIDCollision})
				continue
			}
			ps.byID[id] = e
		}
	}
}

// lookup finds the entry for a datagram's connection id at epoch.
func (ps *peerSet) lookup(id connID, epoch int64) *peerEntry {
	if epoch != ps.epoch {
		ps.reindex(epoch)
	}
	return ps.byID[id]
}
