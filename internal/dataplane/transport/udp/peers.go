package udp

import (
	"bytes"
	"crypto/cipher"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// peerEntry is one accepted credential, indexed by the connection id its
// dialer's datagrams carry.
type peerEntry struct {
	link  transport.PeerLink
	inID  ConnID // dialer to listener
	outID ConnID // listener to dialer
}

func (e *peerEntry) sameAs(o *peerEntry) bool {
	return o != nil && e.link.Peer == o.link.Peer &&
		bytes.Equal(e.link.Config.Credential.Secret, o.link.Config.Credential.Secret)
}

func (e *peerEntry) aead(s session, dir direction) cipher.AEAD {
	return newAEAD(e.link.Config.Credential.Secret, s, dir)
}

// indexPeers skips unusable credentials and, should two secrets ever derive
// the same connection id, all but the first.
func indexPeers(links []transport.PeerLink) map[ConnID]*peerEntry {
	index := make(map[ConnID]*peerEntry, len(links))
	for _, pl := range links {
		if pl.Config.Credential.Validate() != nil {
			continue
		}
		secret := pl.Config.Credential.Secret
		e := &peerEntry{link: pl, inID: connIDFor(secret, toListener), outID: connIDFor(secret, toDialer)}
		if _, dup := index[e.inID]; !dup {
			index[e.inID] = e
		}
	}
	return index
}
