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

// newTable checks every peer link: one reality refuses is dropped, and so
// is every link sharing a short id with another, refused or not (all of
// them, not one guessed).
func newTable(t *Transport, links []transport.PeerLink) table {
	tab := table{links: make(map[shortID]transport.PeerLink, len(links)), refused: map[shortID]error{}}
	shared := map[shortID]bool{}
	errShared := invalid("a short id another peer link has too")
	for _, pl := range links {
		id, err := parseShortID(pl.Verifier)
		if err == nil {
			err = t.CheckInbound(pl)
		}
		if err != nil {
			if len(pl.Verifier) == ShortIDSize {
				tab.refused[id] = err
			}
			tab.rejected = append(tab.rejected, transport.PeerError{Peer: pl.Peer, Err: err})
			continue
		}
		if first, ok := tab.links[id]; ok {
			shared[id] = true
			delete(tab.links, id)
			tab.rejected = append(tab.rejected, transport.PeerError{Peer: first.Peer, Err: errShared})
		}
		if shared[id] {
			tab.rejected = append(tab.rejected, transport.PeerError{Peer: pl.Peer, Err: errShared})
			continue
		}
		tab.links[id] = pl
	}
	for id := range tab.refused {
		if pl, ok := tab.links[id]; ok {
			delete(tab.links, id)
			tab.rejected = append(tab.rejected, transport.PeerError{Peer: pl.Peer, Err: errShared})
		}
	}
	return tab
}
