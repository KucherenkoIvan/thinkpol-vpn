package udp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

func firstFrame(o opened) []byte {
	p, _ := nextFrame(o.frames)
	return p
}

// sealFrames seals frames as they are, the way a sender that batches or
// sends cover would: each packet framed, then padding bytes of zeros.
func sealFrames(secret []byte, dir direction, sender senderID, now time.Time, counter uint64, frames []byte) []byte {
	id := connIDFor(secret, dir, epochOf(now))
	d := append([]byte(nil), id[:]...)
	nonce := make([]byte, nonceSize)
	_, _ = rand.Read(nonce)
	d = append(d, nonce...)
	plain := append([]byte(nil), sender[:]...)
	plain = binary.BigEndian.AppendUint32(plain, uint32(now.Unix()))
	plain = binary.BigEndian.AppendUint64(plain, counter)
	plain = append(plain, frames...)
	return newAEAD(secret, dir).Seal(d, nonce, plain, id[:])
}

func frames(packets ...[]byte) []byte {
	var b []byte
	for _, p := range packets {
		b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
		b = append(b, p...)
	}
	return b
}

func TestPaddingStaysInsideTheSeal(t *testing.T) {
	secret := randomSecret(t)
	now := time.Now()
	id, sender := connIDFor(secret, toListener, epochOf(now)), newSenderID(now)
	aead := newAEAD(secret, toListener)
	buckets := transport.Buckets(128, 256, 1280)
	for _, n := range []int{1, 50, 54, 55, 182, 183, 1206, 1207, 4000} {
		packet := bytes.Repeat([]byte{0xab}, n)
		d := seal(nil, aead, id, sender, now, 1, packet, buckets)
		want := buckets.Size(Overhead + n)
		if len(d) != want {
			t.Errorf("%d-byte packet: %d-byte datagram, want %d", n, len(d), want)
		}
		o, err := open(nil, aead, d)
		if err != nil || o.packets != 1 || !bytes.Equal(firstFrame(o), packet) {
			t.Fatalf("%d-byte packet: open %+v, %v", n, o, err)
		}
		for i := clearSize; i < len(d)-tagSize; i++ {
			bad := bytes.Clone(d)
			bad[i] ^= 0x80
			if _, err := open(nil, aead, bad); err == nil {
				t.Fatalf("%d-byte packet: flipping byte %d (padding included) went unnoticed", n, i)
			}
		}
	}
	random := transport.Padding{Mode: transport.PadRandom, Min: 10, Max: 20}
	for range 200 {
		d := seal(nil, aead, id, sender, now, 1, []byte("x"), random)
		if pad := len(d) - Overhead - 1; pad < 10 || pad > 20 {
			t.Fatalf("random padding of %d bytes, want 10 to 20", pad)
		}
		if o, err := open(nil, aead, d); err != nil || !bytes.Equal(firstFrame(o), []byte("x")) {
			t.Fatalf("open: %+v, %v", o, err)
		}
	}
}

// Receivers take what a sender that batches or sends cover would send,
// though udp's own senders don't yet: the format is the contract.
func TestFramesAndCover(t *testing.T) {
	secret := randomSecret(t)
	now := time.Now()
	aead := newAEAD(secret, toListener)
	big := bytes.Repeat([]byte{7}, transport.MaxPacketSize)
	for _, tc := range []struct {
		name   string
		frames []byte
		want   [][]byte
	}{
		{"cover", nil, nil},
		{"padded cover", make([]byte, 100), nil},
		{"one trailing byte", append(frames([]byte("a")), 0), [][]byte{[]byte("a")}},
		{"batch", append(frames([]byte("one"), []byte("two"), big), make([]byte, 33)...), [][]byte{[]byte("one"), []byte("two"), big}},
	} {
		o, err := open(nil, aead, sealFrames(secret, toListener, newSenderID(now), now, 1, tc.frames))
		if err != nil || o.packets != len(tc.want) {
			t.Fatalf("%s: %+v, %v", tc.name, o, err)
		}
		var got [][]byte
		for p, rest := nextFrame(o.frames); p != nil; p, rest = nextFrame(rest) {
			got = append(got, p)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: %d packets, want %d", tc.name, len(got), len(tc.want))
		}
		for i := range got {
			if !bytes.Equal(got[i], tc.want[i]) {
				t.Errorf("%s: packet %d differs", tc.name, i)
			}
		}
	}
	for name, body := range map[string][]byte{
		"length past the end":  append(frames([]byte("abc")), 0, 9, 1),
		"packet over the max":  frames(append(big, 1)),
		"truncated last frame": frames([]byte("abcd"))[:4],
	} {
		if _, err := open(nil, aead, sealFrames(secret, toListener, newSenderID(now), now, 1, body)); !errors.Is(err, errMalformed) {
			t.Errorf("%s: %v, want errMalformed", name, err)
		}
	}
}

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
	d := seal(nil, newAEAD(secret, toListener), id, sender, now, 7, packet, transport.Padding{})
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
	if err != nil || o.sender != sender || o.counter != 7 || o.packets != 1 || !bytes.Equal(firstFrame(o), packet) || o.sent.Unix() != now.Unix() {
		t.Fatalf("open: %+v %v", o, err)
	}
	if !o.fresh(now.Add(maxClockSkew)) || o.fresh(now.Add(maxClockSkew+2*time.Second)) || o.fresh(now.Add(-maxClockSkew-2*time.Second)) {
		t.Error("freshness doesn't follow the five-minute bound")
	}
	again := seal(nil, newAEAD(secret, toListener), id, sender, now, 7, packet, transport.Padding{})
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
	for _, n := range []int{0, 1, clearSize, minDatagram - 1, maxDatagram + 1} {
		if _, ok := idOf(make([]byte, n)); ok {
			t.Errorf("accepted a %d-byte datagram", n)
		}
	}
	for _, n := range []int{minDatagram, Overhead + 1, maxDatagram} {
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

// A dialer churning through senders keeps a bounded history that costs
// O(1) per new sender, and a sender it just evicted is still refused.
func TestSenderChurnIsBounded(t *testing.T) {
	var s senders
	now := time.Unix(1_000_000, 0)
	start := time.Now()
	var ids []senderID
	for i := range 200_000 {
		at := now.Add(time.Duration(i) * time.Microsecond)
		id := newSenderID(at)
		ids = append(ids, id)
		if v := s.admit(id, 0, at); v != deliverNewest {
			t.Fatalf("sender %d: %v", i, v)
		}
	}
	// About 0.1 s; a cost per eviction that grew with the history (up to
	// maxEvicted entries) would be ten times that or more. The race
	// detector's instrumentation alone makes it 15 times slower, so under
	// -race the time says nothing about the cost.
	if took := time.Since(start); raceEnabled {
		t.Logf("200000 new senders took %v under the race detector", took)
	} else if took > 2*time.Second {
		t.Fatalf("200000 new senders took %v", took)
	}
	if len(s.evicted.at) > maxEvicted || s.evicted.size > maxEvicted {
		t.Fatalf("%d evicted senders kept, at most %d", len(s.evicted.at), maxEvicted)
	}
	recent := ids[len(ids)-maxSenders-1] // the last one out of the slots
	if v := s.admit(recent, 1, now.Add(time.Second)); v != dropStale {
		t.Fatalf("a just-evicted sender: %v, want refused", v)
	}
}
