package reality

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// listenFor starts a listener accepting peers, with reality's own
// camouflage: the splice to the target.
func listenFor(t *testing.T, tr *Transport, k keys, window uint32, peers ...transport.PeerLink) transport.Listener {
	t.Helper()
	l, err := tr.Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, theTarget(t), window)},
		transport.Admission{Peers: transport.NewPeerTable(peers...)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func peerLink(id []byte) transport.PeerLink {
	return transport.PeerLink{Peer: transporttest.RandomIdentity(), Verifier: id}
}

func dial(t *testing.T, tr *Transport, address string, k keys, id []byte) (transport.Link, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := tr.Dial(ctx, address, transport.DialConfig{Credential: id, Settings: dialSettingsFor(t, k)})
	if err == nil {
		t.Cleanup(func() { _ = l.Close() })
	}
	return l, err
}

func expectNoAccept(t *testing.T, l transport.Listener) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, id, err := l.Accept(ctx); err == nil {
		t.Errorf("accepted %s", id)
	}
}

// splicedWhole waits for the target to have received exactly what the
// dialer sent through tp, and reports whether it did.
func splicedWhole(tg *target, tp *tap) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range tp.captured() {
			for _, r := range tg.received() {
				if len(s) > 0 && bytes.Equal(r, s) {
					return true
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A wrong short id is spliced to the target, raw and whole, and the dialer
// meets the target's real certificate, which fails the dial.
func TestWrongShortIDIsSplicedToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	right, _ := shortIDs()
	wrong, _ := shortIDs()
	l := listenFor(t, tr, k, 0, peerLink(right))
	tp := newTap(t, l.Addr().String())

	if _, err := dial(t, tr, tp.addr(), k, wrong); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("dial with a wrong short id: %v, want %v", err, ErrNotAuthenticated)
	}
	if !splicedWhole(theTarget(t), tp) {
		t.Error("the target didn't receive exactly what the dialer sent")
	}
	expectNoAccept(t, l)
}

// A replayed connection, an authenticated one sent again byte for byte,
// is spliced to the target like any failed authentication.
func TestReplayIsSplicedToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	l := listenFor(t, tr, k, 0, peerLink(id))
	tp := newTap(t, l.Addr().String())

	client, err := dial(t, tr, tp.addr(), k, id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, _, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WritePacket([]byte("before the replay")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := server.ReadPacket(buf); err != nil {
		t.Fatal(err)
	}

	streams := tp.replay(t)
	if len(streams) != 1 {
		t.Fatalf("captured %d streams, want 1", len(streams))
	}
	if !theTarget(t).receivedExactly(streams[0]) {
		t.Error("the replay wasn't spliced to the target raw and whole")
	}
	expectNoAccept(t, l)
}

// A hello sealed outside the listener's time window is refused; one inside
// it is taken.
func TestAHelloSealedOutsideTheTimeWindowIsRefused(t *testing.T) {
	k := newKeys(t)
	id, _ := shortIDs()
	l := listenFor(t, startedLongAgo(newTransport(Options{})), k, 60, peerLink(id))
	skewed := func(d time.Duration) *Transport {
		return newTransport(Options{Now: func() time.Time { return time.Now().Add(d) }})
	}
	if _, err := dial(t, skewed(-2*time.Minute), l.Addr().String(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("dial sealed 2 minutes ago through a 1-minute window: %v, want %v", err, ErrNotAuthenticated)
	}
	if _, err := dial(t, skewed(-30*time.Second), l.Addr().String(), k, id); err != nil {
		t.Errorf("dial sealed 30 s ago through a 1-minute window: %v", err)
	}
}

// keyShare encodes a key_share extension's data.
func keyShare(shares ...[]byte) []byte {
	var list []byte
	for _, s := range shares {
		list = append(list, s...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

func share(group uint16, size int, fill byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, group)
	b = binary.BigEndian.AppendUint16(b, uint16(size))
	return append(b, bytes.Repeat([]byte{fill}, size)...)
}

// The share the seal is keyed with is chosen as REALITY's server chooses
// it: a hello without X25519MLKEM768 before its X25519 share is refused.
func TestReadShare(t *testing.T) {
	hybrid := share(groupX25519MLKEM768, mlkem768KeySize+32, 0xaa)
	x25519 := share(groupX25519, 32, 0xbb)
	p256 := share(0x0017, 65, 0xcc)
	for _, tc := range []struct {
		name   string
		shares [][]byte
		want   byte // the fill of the share chosen; 0 for none
	}{
		{"hybrid then x25519", [][]byte{hybrid, x25519}, 0xbb},
		{"hybrid alone", [][]byte{hybrid}, 0xaa},
		{"other groups skipped", [][]byte{p256, hybrid, p256, x25519}, 0xbb},
		{"x25519 alone", [][]byte{x25519}, 0},
		{"x25519 before hybrid", [][]byte{x25519, hybrid}, 0},
		{"two hybrids", [][]byte{hybrid, hybrid, x25519}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := readShare(keyShare(tc.shares...))
			if !ok {
				t.Fatal("malformed")
			}
			switch {
			case tc.want == 0 && got != nil:
				t.Errorf("chose a share, want none")
			case tc.want != 0 && (len(got) != 32 || got[0] != tc.want):
				t.Errorf("chose %x, want 32 bytes of %#x", got, tc.want)
			}
		})
	}
}

// helloRecord builds a Chrome ClientHello sealed with id and sent for the
// listener key, and returns it as one TLS record.
func helloRecord(t *testing.T, listener *ecdh.PrivateKey, id shortID, sent uint32) []byte {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	uc := utls.UClient(c, &utls.Config{ServerName: serverName}, utls.HelloChrome_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if _, err := sealHello(uc, listener.PublicKey(), id, sent); err != nil {
		t.Fatal(err)
	}
	raw := uc.HandshakeState.Hello.Raw
	rec := []byte{recordTypeHandshake, 3, 1}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(raw)))
	return append(rec, raw...)
}

// The seal opens under the listener's key only, and only for the hello it
// was sealed into.
func TestTheSealOpensOnlyUnderTheListenersKey(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := shortID{1, 2, 3, 4, 5, 6, 7, 8}
	const sent = 1_800_000_000
	rec := helloRecord(t, key, id, sent)

	h, err := parseHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h.serverName != serverName {
		t.Errorf("server name %q, want %q", h.serverName, serverName)
	}
	s, err := open(key, h)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s.shortID != id || s.sent != sent {
		t.Errorf("opened %x at %d, want %x at %d", s.shortID, s.sent, id, sent)
	}
	if _, err := open(other, h); err == nil {
		t.Error("another listener's key opened the seal")
	}

	// The seal covers the whole hello: change the first cipher suite.
	tampered := bytes.Clone(rec)
	tampered[recordHeaderSize+sessionIDOffset+sessionIDSize+3] ^= 1
	h, err = parseHello(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(key, h); err == nil {
		t.Error("a hello changed after sealing opened")
	}
}

// Padding frames bring a record to its bucket exactly, and the receiver
// reads the packets back from the stream alone.
func TestPaddingFramesFillTheBucketAndReadBackFromTheStream(t *testing.T) {
	packet := []byte("a packet")
	unpadded := frameHeader + len(packet) + recordOverhead
	var stream []byte
	for _, extra := range []int{0, 1, 2, 3, 300, maxUnit - unpadded} {
		before := len(stream)
		stream = appendUnit(stream, packet, transporttest.Buckets(unpadded+extra))
		if got := len(stream) - before + recordOverhead; got != unpadded+extra {
			t.Errorf("padded by %d: a %d-byte record, want %d", extra, got, unpadded+extra)
		}
	}
	r := bufio.NewReader(bytes.NewReader(stream))
	buf := make([]byte, 64)
	for i := range 6 {
		n, err := readPacket(r, buf)
		if err != nil || !bytes.Equal(buf[:n], packet) {
			t.Fatalf("packet %d: %q, %v", i, buf[:n], err)
		}
	}
	if _, err := readPacket(r, buf); err == nil {
		t.Error("read past the stream's end")
	}
}

func sessionIDOf(i int) []byte {
	b := make([]byte, sessionIDSize)
	binary.BigEndian.PutUint32(b, uint32(i))
	return b
}

// admits is c.admit's verdict.
func (c *replayCache) admits(id shortID, sessionID []byte, sent uint32, now time.Time) bool {
	admitted, _ := c.admit(id, sessionID, sent, now)
	return admitted
}

// A hello admitted while a refresh prunes its space's cache is
// remembered, whichever goes first: its replay is refused, never let
// through because it went into a cache prune dropped. The window is a
// few instructions wide: the race detector's scheduling finds it within
// these rounds, a plain run rarely does.
func TestAHelloAdmittedWhileItsSpaceIsPrunedIsRemembered(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	sent := uint32(at.Unix())
	space := randomSpace()
	for i := range 5000 {
		r := newReplays(time.Minute)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var admitted bool
		wg.Go(func() {
			<-start
			admitted = r.admit(space, shortID{1}, sessionIDOf(i), sent, at)
		})
		wg.Go(func() {
			<-start
			r.prune(nil, at)
		})
		close(start)
		wg.Wait()
		if !admitted {
			t.Fatalf("round %d: a fresh hello refused", i)
		}
		if r.admit(space, shortID{1}, sessionIDOf(i), sent, at) {
			t.Fatalf("round %d: the replay of a hello admitted while its space was pruned admitted", i)
		}
	}
}

// The replay cache admits a session id once, forgets what left the
// window, and so admits again once time moves on.
func TestTheReplayCacheAdmitsOnceAndForgetsWhatLeftTheWindow(t *testing.T) {
	const window = time.Minute
	c := newReplayCache(window)
	at := time.Unix(1_800_000_000, 0)
	sent := uint32(at.Unix())
	id := shortID{1}
	if !c.admits(id, sessionIDOf(0), sent, at) || c.admits(id, sessionIDOf(0), sent, at) {
		t.Fatal("a session id admitted other than once")
	}
	if c.admits(id, sessionIDOf(1), sent-uint32(window/time.Second)-1, at) {
		t.Error("a hello sealed before the window admitted")
	}
	for i := 1; i < replayShare; i++ {
		c.admits(id, sessionIDOf(i), sent, at)
	}
	if c.admits(id, sessionIDOf(replayShare), sent, at) {
		t.Fatal("a full share admitted")
	}
	later := at.Add(window + time.Second)
	if !c.admits(id, sessionIDOf(replayShare), uint32(later.Unix()), later) {
		t.Error("a full share still refuses once its entries left the window")
	}
}

// One short id dialling as fast as it can fills its own share of the
// replay cache, never the cache: another short id is still admitted.
func TestOneShortIDFillsOnlyItsOwnReplayShare(t *testing.T) {
	c := newReplayCache(time.Minute)
	at := time.Unix(1_800_000_000, 0)
	sent := uint32(at.Unix())
	flood, other := shortID{1}, shortID{2}
	admitted := 0
	for i := range maxRemembered {
		if c.admits(flood, sessionIDOf(i), sent, at) {
			admitted++
		}
	}
	if admitted != replayShare {
		t.Errorf("one short id admitted %d hellos, want its share, %d", admitted, replayShare)
	}
	if !c.admits(other, sessionIDOf(0), sent, at) {
		t.Error("another short id's fresh hello refused")
	}
}

// Hellos sealed ahead of the clock hold only themselves: once the rest of
// a full cache left the window, a new short id is admitted.
func TestASealAheadOfTheClockHoldsOnlyItself(t *testing.T) {
	const window = time.Minute
	c := newReplayCache(window)
	at := time.Unix(1_800_000_000, 0)
	ahead := uint32(at.Add(window).Unix())
	for n := range maxRemembered / replayShare {
		id := shortID{byte(n), byte(n >> 8), 1}
		if !c.admits(id, sessionIDOf(0), ahead, at) {
			t.Fatalf("short id %d: a hello sealed at the window's edge refused", n)
		}
		for i := 1; i < replayShare; i++ {
			c.admits(id, sessionIDOf(i), uint32(at.Unix()), at)
		}
	}
	if c.admits(shortID{9}, sessionIDOf(0), uint32(at.Unix()), at) {
		t.Fatal("a full cache admitted")
	}
	later := at.Add(window + time.Second)
	if !c.admits(shortID{9}, sessionIDOf(0), uint32(later.Unix()), later) {
		t.Error("a full cache still refuses once all but the hellos sealed ahead left the window")
	}
}

// One space filling its replay cache, with as many credentials as it
// takes, never refuses another space's hello: each space has a cache of
// its own.
func TestOneSpaceFillingItsReplayCacheDoesntRefuseAnothers(t *testing.T) {
	r := newReplays(time.Minute)
	at := time.Unix(1_800_000_000, 0)
	sent := uint32(at.Unix())
	guest, owner := randomSpace(), randomSpace()
	for n := range maxRemembered / replayShare {
		id := shortID{byte(n), byte(n >> 8), 1}
		for i := range replayShare {
			r.admit(guest, id, sessionIDOf(i), sent, at)
		}
	}
	if r.admit(guest, shortID{9}, sessionIDOf(0), sent, at) {
		t.Fatal("the guest space's full cache admitted")
	}
	if !r.admit(owner, shortID{9}, sessionIDOf(0), sent, at) {
		t.Error("another space's fresh hello refused while the guest's cache is full")
	}
}

// A space's cache outlives its leaving the table while it remembers
// anything fresh, so a space that comes back still refuses its replays.
func TestASpacesReplayCacheIsDroppedOnlyOnceItLeftTheWindow(t *testing.T) {
	r := newReplays(time.Minute)
	at := time.Unix(1_800_000_000, 0)
	space := randomSpace()
	if !r.admit(space, shortID{1}, sessionIDOf(0), uint32(at.Unix()), at) {
		t.Fatal("a fresh hello refused")
	}
	r.prune(nil, at)
	if r.admit(space, shortID{1}, sessionIDOf(0), uint32(at.Unix()), at) {
		t.Fatal("a replay admitted after its space left the table")
	}
	later := at.Add(time.Minute + time.Second)
	r.prune(nil, later)
	if len(r.bySpace) != 0 {
		t.Errorf("%d caches kept once all they remembered left the window", len(r.bySpace))
	}
}

// Two links of different spaces sharing a short id: the one already in
// the table stays and the newcomer is rejected, so one space's map can't
// knock out another's link by listing its short id; with neither in the
// table, both are rejected, as are two of one space, and another space's
// refused entry doesn't close the incumbent.
func TestASharedShortIDAcrossSpacesRejectsTheNewcomer(t *testing.T) {
	tr := newTransport(Options{})
	id, _ := shortIDs()
	link := func(space transport.SpaceID) transport.PeerLink {
		pl := peerLink(id)
		pl.Peer.Space = space
		return pl
	}
	owner, guest := link(randomSpace()), link(randomSpace())
	sid := shortID(id)
	rejected := func(tab table) []transport.Identity {
		var out []transport.Identity
		for _, e := range tab.rejected {
			out = append(out, e.Peer)
		}
		return out
	}

	first := newTable(tr, []transport.PeerLink{owner}, nil)
	tab := newTable(tr, []transport.PeerLink{guest, owner}, first.links)
	if got := tab.links[sid]; got.Peer != owner.Peer || !slices.Equal(rejected(tab), []transport.Identity{guest.Peer}) {
		t.Errorf("the incumbent's short id listed by a newcomer: kept %v, rejected %v", got.Peer, rejected(tab))
	}
	if both := newTable(tr, []transport.PeerLink{guest, owner}, nil); len(both.links) != 0 || len(both.rejected) != 2 {
		t.Errorf("neither in the table before: kept %v, rejected %v", both.links, rejected(both))
	}
	twice := link(owner.Peer.Space)
	twice.Peer.Node[0]++
	if same := newTable(tr, []transport.PeerLink{owner, twice}, first.links); len(same.links) != 0 || len(same.rejected) != 2 {
		t.Errorf("two of one space: kept %v, rejected %v", same.links, rejected(same))
	}
	bad := guest
	bad.Settings = []byte{0xff}
	refused := newTable(tr, []transport.PeerLink{bad, owner}, first.links)
	if got := refused.links[sid]; got.Peer != owner.Peer || refused.refused[sid] != nil {
		t.Errorf("another space's refused entry: kept %v, refused %v", got.Peer, refused.refused[sid])
	}
}

// Only a certificate whose signature is the HMAC of its key under the auth
// key proves the listener's key; a real certificate never does.
func TestOnlyREALITYsCertificateProvesTheKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	real, err := x509.CreateCertificate(nil, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	authKey := bytes.Repeat([]byte{7}, 32)
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	// The signature, a BIT STRING, ends the certificate, and an Ed25519
	// signature is as long as an HMAC-SHA512.
	proving := bytes.Clone(real)
	copy(proving[len(proving)-sha512.Size:], mac.Sum(nil))

	if !provesKey([][]byte{proving}, authKey) {
		t.Error("REALITY's certificate didn't prove the key")
	}
	if provesKey([][]byte{proving}, bytes.Repeat([]byte{8}, 32)) {
		t.Error("a certificate proved another auth key")
	}
	if provesKey([][]byte{real}, authKey) {
		t.Error("a real certificate proved the key")
	}
}

// A link whose shaping asks for no padding pads every record to MinRecord,
// both ways, as a capture of what the dialer and the listener send shows:
// no record of application data after the handshake is smaller. One the
// map pads to buckets is padded as it says.
func TestRecordsArePaddedToMinRecordByDefault(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	for _, c := range []struct {
		name    string
		shaping transport.Shaping
		want    int
	}{{"no shaping", transport.Shaping{}, MinRecord}, {"buckets", transport.Shaping{Padding: transporttest.Buckets(1024)}, 1024}} {
		t.Run(c.name, func(t *testing.T) {
			pl := peerLink(id)
			pl.Shaping = c.shaping
			l := listenFor(t, tr, k, 0, pl)
			tp := newTap(t, l.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := tr.Dial(ctx, tp.addr(), transport.DialConfig{Credential: id, Settings: dialSettingsFor(t, k), Shaping: c.shaping})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			server, _, err := l.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			const packets = 3
			for range packets {
				if err := client.WritePacket([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				if _, err := server.ReadPacket(make([]byte, 64)); err != nil {
					t.Fatal(err)
				}
				if err := server.WritePacket([]byte("pong")); err != nil {
					t.Fatal(err)
				}
				if _, err := client.ReadPacket(make([]byte, 64)); err != nil {
					t.Fatal(err)
				}
			}
			for _, way := range []struct {
				name   string
				stream []byte
			}{{"dialer → listener", tp.captured()[0]}, {"listener → dialer", tp.answered()[0]}} {
				sizes := appDataRecords(way.stream)
				if len(sizes) < packets {
					t.Fatalf("%s: records %v", way.name, sizes)
				}
				for _, size := range sizes[len(sizes)-packets:] {
					if size != c.want {
						t.Errorf("%s: a packet's record of %d bytes, want %d (records %v)", way.name, size, c.want, sizes)
					}
				}
			}
		})
	}
}

// appDataRecords is the sizes of the application-data records of stream,
// headers included.
func appDataRecords(stream []byte) []int {
	var sizes []int
	for len(stream) >= recordHeaderSize {
		size := recordHeaderSize + (int(stream[3])<<8 | int(stream[4]))
		if size > len(stream) {
			break
		}
		if stream[0] == 23 {
			sizes = append(sizes, size)
		}
		stream = stream[size:]
	}
	return sizes
}
