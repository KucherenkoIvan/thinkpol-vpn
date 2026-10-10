package udp

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomSecret(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConnIDsAreKeyedAndPerDirection(t *testing.T) {
	a, b := randomSecret(t), randomSecret(t)
	if again := connIDFor(bytes.Clone(a), toListener); again != connIDFor(a, toListener) {
		t.Fatal("connection id is not deterministic")
	}
	ids := map[ConnID]string{}
	for name, id := range map[string]ConnID{
		"a to listener": connIDFor(a, toListener), "a to dialer": connIDFor(a, toDialer),
		"b to listener": connIDFor(b, toListener), "b to dialer": connIDFor(b, toDialer),
	} {
		if other, dup := ids[id]; dup {
			t.Fatalf("%s and %s share a connection id", name, other)
		}
		ids[id] = name
	}
}

func TestSealOpenAndTamper(t *testing.T) {
	secret := randomSecret(t)
	id, sender := connIDFor(secret, toListener), newSenderID()
	packet := []byte("a packet that must not be visible on the wire")
	d := seal(nil, newAEAD(secret, toListener), id, sender, 7, packet)
	if len(d) != len(packet)+Overhead {
		t.Fatalf("datagram is %d bytes, want %d", len(d), len(packet)+Overhead)
	}
	if bytes.Contains(d, packet[:8]) {
		t.Fatal("the packet shows through")
	}
	if got, ok := connIDOf(d); !ok || got != id {
		t.Fatalf("connection id %x, want %x", got, id)
	}
	gotSender, counter, got, err := open(nil, newAEAD(secret, toListener), d)
	if err != nil || gotSender != sender || counter != 7 || !bytes.Equal(got, packet) {
		t.Fatalf("open: %x %d %q %v", gotSender, counter, got, err)
	}
	again := seal(nil, newAEAD(secret, toListener), id, sender, 7, packet)
	if bytes.Equal(again[connIDSize:clearSize], d[connIDSize:clearSize]) {
		t.Fatal("two datagrams share a nonce")
	}
	for _, wrong := range []struct {
		name   string
		secret []byte
		dir    direction
	}{{"other secret", randomSecret(t), toListener}, {"other direction", secret, toDialer}} {
		if _, _, _, err := open(nil, newAEAD(wrong.secret, wrong.dir), d); err == nil {
			t.Errorf("opened with %s", wrong.name)
		}
	}
	for i := range d {
		bad := bytes.Clone(d)
		bad[i] ^= 0x01
		if _, _, _, err := open(nil, newAEAD(secret, toListener), bad); err == nil {
			t.Fatalf("flipping a bit of byte %d went unnoticed", i)
		}
	}
}

func TestConnIDOfBounds(t *testing.T) {
	for _, n := range []int{0, 1, clearSize, Overhead, maxDatagram + 1} {
		if _, ok := connIDOf(make([]byte, n)); ok {
			t.Errorf("accepted a %d-byte datagram", n)
		}
	}
	for _, n := range []int{Overhead + 1, maxDatagram} {
		if _, ok := connIDOf(make([]byte, n)); !ok {
			t.Errorf("rejected a %d-byte datagram", n)
		}
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	accept := func(c uint64, want bool) {
		t.Helper()
		if got := w.accept(c); got != want {
			t.Fatalf("accept(%d) = %v, want %v", c, got, want)
		}
	}
	accept(0, true)
	accept(0, false)
	accept(2, true)
	accept(1, true) // reordered, inside the window
	accept(1, false)
	accept(2, false)
	accept(replayWindowSize+100, true)
	accept(100, false) // fell out of the window
	accept(101, true)  // the oldest still inside
	accept(101, false)
	accept(replayWindowSize+50, true)
	accept(1_000_000, true) // a jump clears the ring
	accept(1_000_000-replayWindowSize+1, true)
	accept(1_000_000-replayWindowSize, false)
	accept(rejectAfterMessages, false)
}

func TestReplayWindowAgainstAModel(t *testing.T) {
	var w replayWindow
	seen := map[uint64]bool{}
	var highest uint64
	buf := make([]byte, 2)
	base := uint64(0)
	for range 100_000 {
		_, _ = rand.Read(buf)
		base += uint64(buf[0] % 8)
		c := base + uint64(buf[1])*16 // up to ~4000 ahead of the base: reorders across the window edge
		want := !seen[c] && (len(seen) == 0 || c > highest || highest-c < replayWindowSize)
		if got := w.accept(c); got != want {
			t.Fatalf("accept(%d) with highest %d = %v, want %v", c, highest, got, want)
		}
		if want {
			seen[c] = true
			highest = max(highest, c)
		}
	}
}

func TestSenderWindows(t *testing.T) {
	var s senderWindows
	accept := func(sender senderID, counter uint64, wantFresh, wantNewest bool) {
		t.Helper()
		if fresh, newest := s.accept(sender, counter); fresh != wantFresh || newest != wantNewest {
			t.Fatalf("accept(%x, %d) = %v, %v; want %v, %v", sender[:2], counter, fresh, newest, wantFresh, wantNewest)
		}
	}
	a, b := newSenderID(), newSenderID()
	accept(a, 10, true, true)
	accept(a, 10, false, false)
	accept(a, 5, true, false) // reordered: fresh, not the newest
	accept(b, 0, true, true)  // a redial starts again at zero
	accept(a, 11, true, true) // and doesn't disturb the old sender
	accept(b, 0, false, false)
	for range maxSenders {
		accept(newSenderID(), 0, true, true)
	}
	accept(a, 10, true, true) // evicted: a pre-filter forgets
}
