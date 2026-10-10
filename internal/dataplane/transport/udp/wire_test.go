package udp

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func randomSecret(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConnIDsAreKeyedPerDirectionAndHour(t *testing.T) {
	a, b := randomSecret(t), randomSecret(t)
	if again := connIDFor(bytes.Clone(a), toListener, 7); again != connIDFor(a, toListener, 7) {
		t.Fatal("connection id is not deterministic")
	}
	ids := map[connID]string{}
	for name, id := range map[string]connID{
		"a to listener": connIDFor(a, toListener, 7), "a to dialer": connIDFor(a, toDialer, 7),
		"b to listener": connIDFor(b, toListener, 7), "b to dialer": connIDFor(b, toDialer, 7),
		"a to listener, next hour": connIDFor(a, toListener, 8),
	} {
		if other, dup := ids[id]; dup {
			t.Fatalf("%s and %s share a connection id", name, other)
		}
		ids[id] = name
	}
	var w idWindow
	for e, want := range map[int64]bool{5: false, 6: true, 7: true, 8: true, 9: false} {
		if got := w.recognises(a, toListener, 7, connIDFor(a, toListener, e)); got != want {
			t.Errorf("at hour 7, the id of hour %d recognised: %v, want %v", e, got, want)
		}
	}
}

func TestSendersAreOrderedByCreation(t *testing.T) {
	now := time.Now()
	prev := newSenderID(now)
	for range 1000 {
		s := newSenderID(now) // even with a clock that stands still
		if s.created() <= prev.created() {
			t.Fatalf("created %d after %d", s.created(), prev.created())
		}
		prev = s
	}
}

func TestSealOpenAndTamper(t *testing.T) {
	secret := randomSecret(t)
	now := time.Now().Truncate(time.Second) // what the seal carries
	id, sender := connIDFor(secret, toListener, epochOf(now)), newSenderID(now)
	packet := []byte("a packet that must not be visible on the wire")
	d := seal(nil, newAEAD(secret, toListener), id, sender, now, 7, packet)
	if len(d) != len(packet)+Overhead {
		t.Fatalf("datagram is %d bytes, want %d", len(d), len(packet)+Overhead)
	}
	if bytes.Contains(d, packet[:8]) {
		t.Fatal("the packet shows through")
	}
	if got, ok := idOf(d); !ok || got != id {
		t.Fatalf("connection id %x, want %x", got, id)
	}
	o, err := open(nil, newAEAD(secret, toListener), d)
	if err != nil || o.sender != sender || o.counter != 7 || !bytes.Equal(o.packet, packet) || o.sent.Unix() != now.Unix() {
		t.Fatalf("open: %+v %v", o, err)
	}
	if !o.fresh(now.Add(maxClockSkew)) || o.fresh(now.Add(maxClockSkew+2*time.Second)) || o.fresh(now.Add(-maxClockSkew-2*time.Second)) {
		t.Error("freshness doesn't follow the five-minute bound")
	}
	again := seal(nil, newAEAD(secret, toListener), id, sender, now, 7, packet)
	if bytes.Equal(again[connIDSize:clearSize], d[connIDSize:clearSize]) {
		t.Fatal("two datagrams share a nonce")
	}
	for _, wrong := range []struct {
		name   string
		secret []byte
		dir    direction
	}{{"other secret", randomSecret(t), toListener}, {"other direction", secret, toDialer}} {
		if _, err := open(nil, newAEAD(wrong.secret, wrong.dir), d); err == nil {
			t.Errorf("opened with %s", wrong.name)
		}
	}
	for i := range d {
		bad := bytes.Clone(d)
		bad[i] ^= 0x01
		if _, err := open(nil, newAEAD(secret, toListener), bad); err == nil {
			t.Fatalf("flipping a bit of byte %d went unnoticed", i)
		}
	}
}

func TestIDOfBounds(t *testing.T) {
	for _, n := range []int{0, 1, clearSize, Overhead, maxDatagram + 1} {
		if _, ok := idOf(make([]byte, n)); ok {
			t.Errorf("accepted a %d-byte datagram", n)
		}
	}
	for _, n := range []int{Overhead + 1, maxDatagram} {
		if _, ok := idOf(make([]byte, n)); !ok {
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

func TestSenderAdmission(t *testing.T) {
	now := time.Now()
	sender := func(at time.Time) senderID { return newSenderID(at) }
	var s senders
	admit := func(id senderID, counter uint64, at time.Time, want verdict) {
		t.Helper()
		if got := s.admit(id, counter, at); got != want {
			t.Fatalf("admit(created %d, %d) = %v, want %v", id.created(), counter, got, want)
		}
	}
	old, cur := sender(now.Add(-time.Minute)), sender(now)
	admit(cur, 10, now, deliverNewest)
	admit(cur, 10, now, dropReplay)
	admit(cur, 5, now, deliver) // reordered: delivered, doesn't move the address
	admit(old, 0, now, dropStale)
	newer := sender(now.Add(time.Second))
	admit(newer, 0, now, deliverNewest) // a redial takes over
	admit(cur, 11, now, deliver)        // and the old one no longer moves the address
	// An older sender takes over only once the current one is quiet.
	admit(old, 1, now.Add(senderTakeover), dropStale)
	admit(old, 2, now.Add(senderTakeover+time.Second), deliverNewest)
	// Never more than maxSenders remembered, and never the current one forgotten.
	for i := range 2 * maxSenders {
		admit(sender(now.Add(time.Duration(i+2)*time.Minute)), 0, now.Add(senderTakeover+time.Second), deliverNewest)
	}
	last := s.current.id
	admit(last, 1, now.Add(senderTakeover+time.Second), deliverNewest)
}
