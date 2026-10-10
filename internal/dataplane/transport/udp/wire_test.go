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

func TestSessionsOnlyGrow(t *testing.T) {
	prev := newSession()
	for range 1000 {
		s := newSession()
		if s.epoch() <= prev.epoch() {
			t.Fatalf("epoch %d after %d", s.epoch(), prev.epoch())
		}
		prev = s
	}
}

func TestSealOpenAndTamper(t *testing.T) {
	secret := randomSecret(t)
	s := newSession()
	h := header{id: connIDFor(secret, toListener), sess: s, counter: 7}
	packet := []byte("a packet that must not be visible on the wire")
	d := seal(nil, newAEAD(secret, s, toListener), h, packet)
	if len(d) != len(packet)+Overhead {
		t.Fatalf("datagram is %d bytes, want %d", len(d), len(packet)+Overhead)
	}
	if bytes.Contains(d, packet[:8]) {
		t.Fatal("the packet shows through")
	}
	parsed, ok := parseHeader(d)
	if !ok || parsed != h {
		t.Fatalf("parsed %+v, want %+v", parsed, h)
	}
	got, err := open(nil, newAEAD(secret, s, toListener), parsed, d)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("open: %q, %v", got, err)
	}
	for _, wrong := range []struct {
		name   string
		secret []byte
		dir    direction
	}{{"other secret", randomSecret(t), toListener}, {"other direction", secret, toDialer}} {
		if _, err := open(nil, newAEAD(wrong.secret, s, wrong.dir), parsed, d); err == nil {
			t.Errorf("opened with %s", wrong.name)
		}
	}
	for i := range d {
		bad := bytes.Clone(d)
		bad[i] ^= 0x01
		ph, ok := parseHeader(bad)
		if !ok {
			continue
		}
		if _, err := open(nil, newAEAD(secret, ph.sess, toListener), ph, bad); err == nil {
			t.Fatalf("flipping a bit of byte %d went unnoticed", i)
		}
	}
}

func TestParseHeaderBounds(t *testing.T) {
	for _, n := range []int{0, 1, headerSize, Overhead, maxDatagram + 1} {
		if _, ok := parseHeader(make([]byte, n)); ok {
			t.Errorf("accepted a %d-byte datagram", n)
		}
	}
	for _, n := range []int{Overhead + 1, maxDatagram} {
		if _, ok := parseHeader(make([]byte, n)); !ok {
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

func TestSessionAdmission(t *testing.T) {
	now := time.Now()
	sessionAt := func(epoch uint64) session {
		var s session
		s[7] = byte(epoch)
		return s
	}
	var f flow
	if !f.admits(sessionAt(5), now) {
		t.Fatal("a fresh flow refused its first session")
	}
	f.epoch, f.seen = 5, now
	if f.admits(sessionAt(5), now) || f.admits(sessionAt(4), now) {
		t.Fatal("admitted a session that isn't newer")
	}
	if !f.admits(sessionAt(6), now) {
		t.Fatal("refused a newer session")
	}
	if !f.admits(sessionAt(4), now.Add(sessionIdleTimeout+time.Second)) {
		t.Fatal("an idle session blocks a dialer whose clock went back")
	}
}
