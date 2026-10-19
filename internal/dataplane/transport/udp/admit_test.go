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
// the AEAD even runs. The measured run admits a new counter each time, so
// it measures the delivered path, not the replay one datagram shown twice
// would take.
func TestAdmitAllocatesNothingOnTheHotPath(t *testing.T) {
	peer := transporttest.SymmetricPeer()
	now := time.Now()
	set := indexPeers([]transport.PeerLink{peer.PeerLink}, epochOf(now))
	table := newSenderHistories()
	// AllocsPerRun warms the closure up once, then measures 100 runs.
	datagrams := make([][]byte, 102)
	for i := range datagrams {
		datagrams[i] = seal(nil, newAEAD(peer.Credential, toListener), connIDFor(peer.Credential, toListener, epochOf(now)), newSenderID(now), now, uint64(i), []byte("packet"), transport.Padding{})
	}
	dst := make([]byte, 0, maxDatagram)
	var ladder admitLadder
	delivered := 0
	admit := func() {
		if _, o, v := ladder.admit(dst[:0], set, table, datagrams[delivered], now); v != deliverNewest || o.packets != 1 {
			t.Fatalf("datagram %d didn't deliver: %v", delivered, v)
		}
		delivered++
	}
	admit()
	if allocs := testing.AllocsPerRun(100, admit); allocs != 0 {
		t.Fatalf("admit allocates %v times per datagram on the hot path", allocs)
	}
}
