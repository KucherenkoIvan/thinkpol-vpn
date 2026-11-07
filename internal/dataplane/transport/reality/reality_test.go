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
	tr := New(Options{})
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
	tr := New(Options{})
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

// The listener's time window bounds the sealed time.
func TestTimeWindow(t *testing.T) {
	k := newKeys(t)
	id, _ := shortIDs()
	l := listenFor(t, New(Options{}), k, 60, peerLink(id))
	skewed := func(d time.Duration) *Transport {
		return New(Options{Now: func() time.Time { return time.Now().Add(d) }})
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

func TestSealOpens(t *testing.T) {
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
func TestPaddingFrames(t *testing.T) {
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

// The replay cache forgets what left the window, so a full cache admits
// again once time moves on.
func TestReplayCache(t *testing.T) {
	const window = time.Minute
	c := newReplayCache(window)
	at := time.Unix(1_800_000_000, 0)
	sent := uint32(at.Unix())
	id := func(i int) []byte {
		b := make([]byte, sessionIDSize)
		binary.BigEndian.PutUint32(b, uint32(i))
		return b
	}
	if !c.admit(id(0), sent, at) || c.admit(id(0), sent, at) {
		t.Fatal("a session id admitted other than once")
	}
	if c.admit(id(1), sent-uint32(window/time.Second)-1, at) {
		t.Error("a hello sealed before the window admitted")
	}
	for i := 1; i < maxRemembered; i++ {
		c.admit(id(i), sent, at)
	}
	if c.admit(id(maxRemembered), sent, at) {
		t.Fatal("a full cache admitted")
	}
	later := at.Add(window + time.Second)
	if !c.admit(id(maxRemembered), uint32(later.Unix()), later) {
		t.Error("a full cache still refuses once its entries left the window")
	}
}

// Only a certificate whose signature is the HMAC of its key under the auth
// key proves the listener's key; a real certificate never does.
func TestProvesKey(t *testing.T) {
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
