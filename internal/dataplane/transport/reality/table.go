package reality

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"

// table is a peer table as reality reads it: the links it accepts by short
// id, the short ids whose entry it refuses (each with why), and every peer
// link it can't use.
type table struct {
	links    map[shortID]transport.PeerLink
	refused  map[shortID]error
	rejected []transport.PeerError
}

// newTable checks every peer link, prev being the links of the table it
// replaces. One reality refuses is dropped. Links sharing a short id
// (refused ones included) are all dropped, not one guessed, with one
// exception that keeps one space's map from knocking out another's link:
// when they belong to different spaces and one of them, alone in its
// space, was in prev, that one stays and only the newcomers are dropped.
// With none in prev (both new, or a fresh start) all are dropped.
func newTable(t *Transport, links []transport.PeerLink, prev map[shortID]transport.PeerLink) table {
	tab := table{links: make(map[shortID]transport.PeerLink, len(links)), refused: map[shortID]error{}}
	var order []shortID
	usable := map[shortID][]transport.PeerLink{}
	claims := map[shortID][]transport.SpaceID{} // every entry's space, refused ones too
	for _, pl := range links {
		id, err := parseShortID(pl.Verifier)
		if err == nil {
			err = t.CheckInbound(pl)
		}
		if err != nil {
			if len(pl.Verifier) == ShortIDSize {
				if len(claims[id]) == 0 {
					order = append(order, id)
				}
				claims[id] = append(claims[id], pl.Peer.Space)
				tab.refused[id] = err
			}
			tab.rejected = append(tab.rejected, transport.PeerError{Peer: pl.Peer, Err: err})
			continue
		}
		if len(claims[id]) == 0 {
			order = append(order, id)
		}
		claims[id] = append(claims[id], pl.Peer.Space)
		usable[id] = append(usable[id], pl)
	}
	errShared := invalid("a short id another peer link has too")
	for _, id := range order {
		group := usable[id]
		if len(group) == 1 && len(claims[id]) == 1 {
			tab.links[id] = group[0]
			continue
		}
		kept, keep := incumbent(group, claims[id], prev, id)
		for _, pl := range group {
			if keep && pl.Peer == kept.Peer {
				tab.links[id] = pl
				continue
			}
			tab.rejected = append(tab.rejected, transport.PeerError{Peer: pl.Peer, Err: errShared})
		}
		if keep {
			delete(tab.refused, id) // another space's refused entry: not this link's
		}
	}
	return tab
}

// incumbent is the link of group, the usable links sharing short id id,
// that was prev's and is the only claim on id of its space, if any.
func incumbent(group []transport.PeerLink, spaces []transport.SpaceID, prev map[shortID]transport.PeerLink, id shortID) (transport.PeerLink, bool) {
	old, ok := prev[id]
	if !ok {
		return transport.PeerLink{}, false
	}
	same := 0
	for _, s := range spaces {
		if s == old.Peer.Space {
			same++
		}
	}
	if same != 1 {
		return transport.PeerLink{}, false
	}
	for _, pl := range group {
		if pl.Peer == old.Peer {
			return pl, true
		}
	}
	return transport.PeerLink{}, false
}
