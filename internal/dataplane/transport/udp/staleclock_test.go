package udp

import (
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// TestReplayedOldDatagramDoesNotCountAsStaleClock: a passive tap replaying
// an authenticated datagram of a live sender must not raise clock_skew.
func TestReplayedOldDatagramDoesNotCountAsStaleClock(t *testing.T) {
	c := &clock{}
	tr := New(Options{Now: c.now})
	peers := []transporttest.Peer{transporttest.SymmetricPeer()}
	table := transport.NewPeerTable(peers[0].PeerLink)
	r := tr.Router(table).(*Router)
	now := c.now()
	sender := senderIDFor(now.UnixNano())
	live := seal(nil, newAEAD(peers[0].Credential, toListener), connIDFor(peers[0].Credential, toListener, epochOf(now)), sender, now, 0, []byte("packet"), transport.Padding{})
	if id, v := r.RouteDatagram(live); v != transport.Routed || id != peers[0].Peer {
		t.Fatalf("live: %v %v", v, id)
	}
	old := seal(nil, newAEAD(peers[0].Credential, toListener), connIDFor(peers[0].Credential, toListener, epochOf(now.Add(-6*time.Minute))), sender, now.Add(-6*time.Minute), 0, []byte("packet"), transport.Padding{})
	if id, v := r.RouteDatagram(old); v != transport.Replayed || id != peers[0].Peer {
		t.Fatalf("replayed old sealed time: %v for %s", v, id)
	}
	if got := r.Counters().StaleTimestamp; got != 0 {
		t.Fatalf("stale timestamp %d, want 0", got)
	}
}

// TestGenuinelySkewedPeerCountsAsStaleClock: new counters with an old
// sealed send time are clock skew, not replay.
func TestGenuinelySkewedPeerCountsAsStaleClock(t *testing.T) {
	c := &clock{}
	tr := New(Options{Now: c.now})
	peers := []transporttest.Peer{transporttest.SymmetricPeer()}
	table := transport.NewPeerTable(peers[0].PeerLink)
	r := tr.Router(table).(*Router)
	now := c.now()
	for i := 0; i < 2; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		d := seal(nil, newAEAD(peers[0].Credential, toListener), connIDFor(peers[0].Credential, toListener, epochOf(at)), newSenderID(at), at, uint64(i), []byte("packet"), transport.Padding{})
		if _, v := r.RouteDatagram(d); v != transport.Routed {
			t.Fatalf("packet %d: %v", i, v)
		}
	}
	skewed := seal(nil, newAEAD(peers[0].Credential, toListener), connIDFor(peers[0].Credential, toListener, epochOf(now.Add(-6*time.Minute))), newSenderID(now), now.Add(-6*time.Minute), 99, []byte("packet"), transport.Padding{})
	if id, v := r.RouteDatagram(skewed); v != transport.StaleClock || id != peers[0].Peer {
		t.Fatalf("skewed: %v for %s", v, id)
	}
}

func TestWouldReplay(t *testing.T) {
	var s senders
	now := time.Unix(1_800_000_000, 0)
	id := newSenderID(now)
	if s.wouldReplay(id, 0) {
		t.Fatal("unknown sender")
	}
	if v := s.admit(id, 0, uint32(now.Unix()), now); v != deliverNewest {
		t.Fatal(v)
	}
	if !s.wouldReplay(id, 0) {
		t.Fatal("counter at high water")
	}
	if s.wouldReplay(id, 1) {
		t.Fatal("counter past high water is not replay")
	}
}
