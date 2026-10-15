package path

import "time"

// WatchEvery sets how often a node checks its links, on the wall clock:
// tests with a fake clock check often and step the clock in small steps.
func WatchEvery(o Options, d time.Duration) Options {
	o.watchEvery = d
	return o
}

// LastSeen is the node time of the last sign of life from peer through via.
func (b *Bind) LastSeen(peer, via NodeID) int64 {
	ps := (*b.peers.Load())[peer]
	if ps == nil {
		return 0
	}
	v, ok := ps.eps.Load(via)
	if !ok {
		return 0
	}
	return v.(*peerEndpoint).lastSeen.Load()
}
