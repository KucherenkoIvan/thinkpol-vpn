package udp

import (
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// TestAdmitAllocatesNothingOnTheHotPath pins the cost of the ladder's
// first rungs: the connection id lookup and the history lookup index
// their maps without converting the verifier to a string, which would
// allocate for every datagram that carries a valid connection id, before
// the AEAD even runs.
func TestAdmitAllocatesNothingOnTheHotPath(t *testing.T) {
	peer := transporttest.SymmetricPeer()
	now := time.Now()
	set := indexPeers([]transport.PeerLink{peer.PeerLink}, epochOf(now))
	table := newSenderHistories()
	d := seal(nil, newAEAD(peer.Credential, toListener), connIDFor(peer.Credential, toListener, epochOf(now)), newSenderID(now), now, 0, []byte("packet"), transport.Padding{})
	dst := make([]byte, 0, maxDatagram)
	var ladder admitLadder
	if e, o, v := ladder.admit(dst[:0], set, table, d, now); e == nil || v != deliverNewest || o.packets != 1 {
		t.Fatalf("the first datagram didn't deliver: %v", v)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		ladder.admit(dst[:0], set, table, d, now)
	}); allocs != 0 {
		t.Fatalf("admit allocates %v times per datagram on the hot path", allocs)
	}
}
