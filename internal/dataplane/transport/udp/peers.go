package udp

import (
	"bytes"
	"crypto/cipher"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// peerEntry is one accepted credential, indexed by the connection id its
// dialer's datagrams carry, with the keys derived once.
type peerEntry struct {
	link  transport.PeerLink
	inID  ConnID // dialer to listener
	outID ConnID // listener to dialer
	recv  cipher.AEAD
	send  cipher.AEAD
}

func (e *peerEntry) sameAs(o *peerEntry) bool {
	return o != nil && e.link.Peer == o.link.Peer &&
		bytes.Equal(e.link.Config.Credential.Secret, o.link.Config.Credential.Secret)
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
		id := connIDFor(secret, toListener)
		if _, dup := index[id]; dup {
			continue
		}
		index[id] = &peerEntry{
			link: pl, inID: id, outID: connIDFor(secret, toDialer),
			recv: newAEAD(secret, toListener), send: newAEAD(secret, toDialer),
		}
	}
	return index
}
