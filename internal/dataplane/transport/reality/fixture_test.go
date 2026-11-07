package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

const serverName = "www.example.net"

// target is a local TLS 1.3 site, the camouflage target REALITY imitates:
// it answers any ClientHello for serverName with a self-signed certificate,
// records every byte each connection sends it (reading on after a failed
// handshake, until the far end closes), and answers "site" to a line of
// input after the handshake.
type target struct {
	ln   net.Listener
	cert *x509.Certificate

	mu    sync.Mutex
	conns []*recorder
}

var (
	sharedTarget     *target
	sharedTargetOnce sync.Once
)

// theTarget is one target for the whole test binary: REALITY learns a
// target's records once per process.
func theTarget(t testing.TB) *target {
	sharedTargetOnce.Do(func() { sharedTarget = newTarget(t) })
	return sharedTarget
}

func newTarget(t testing.TB) *target { return newTargetAt(t, "127.0.0.1:0") }

// newTargetAt starts a target listening on address.
func newTargetAt(t testing.TB, address string) *target {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tg := &target{ln: ln, cert: cert}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tg.serve(c, cfg)
		}
	}()
	return tg
}

func (tg *target) serve(c net.Conn, cfg *tls.Config) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	rec := &recorder{Conn: c}
	tg.mu.Lock()
	tg.conns = append(tg.conns, rec)
	tg.mu.Unlock()
	tc := tls.Server(rec, cfg)
	if err := tc.Handshake(); err != nil {
		_, _ = io.Copy(io.Discard, rec)
		return
	}
	buf := make([]byte, 64)
	if _, err := tc.Read(buf); err == nil {
		_, _ = tc.Write([]byte("site"))
	}
}

func (tg *target) addr() string { return tg.ln.Addr().String() }

// received reports what each connection the target has had so far sent
// it.
func (tg *target) received() [][]byte {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	out := make([][]byte, len(tg.conns))
	for i, r := range tg.conns {
		out[i] = r.bytes()
	}
	return out
}

// receivedExactly waits for a connection to the target to have sent it
// exactly stream, and reports whether one did.
func (tg *target) receivedExactly(stream []byte) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, b := range tg.received() {
			if bytes.Equal(b, stream) {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// recorder keeps what was read from a connection.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	if len(r.buf) < 1<<15 {
		r.buf = append(r.buf, p[:n]...)
	}
	r.mu.Unlock()
	return n, err
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf)
}

// keys is a listener's key pair.
type keys struct{ private, public []byte }

func newKeys(t testing.TB) keys {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{k.Bytes(), k.PublicKey().Bytes()}
}

func mustMarshal(t testing.TB, m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listenSettingsFor(t testing.TB, k keys, tg *target, window uint32) []byte {
	return mustMarshal(t, &transportv1.RealityListenSettings{
		PrivateKey: k.private, Target: tg.addr(), ServerNames: []string{serverName}, TimeWindowS: window,
	})
}

func dialSettingsFor(t testing.TB, k keys) []byte {
	return mustMarshal(t, &transportv1.RealityDialSettings{ServerName: serverName, PublicKey: k.public})
}

// shortIDs makes a credential and its verifier: the same 8 random bytes.
func shortIDs() (credential, verifier []byte) {
	id := make([]byte, ShortIDSize)
	_, _ = rand.Read(id)
	return id, id
}

// tap is a TCP man in the middle in front of an address: it passes
// connections through and keeps what each dialer sent.
type tap struct {
	ln      net.Listener
	address string

	mu      sync.Mutex
	streams []*bytes.Buffer
}

func newTap(t *testing.T, address string) *tap {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tp := &tap{ln: ln, address: address}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", address)
			if err != nil {
				_ = c.Close()
				continue
			}
			buf := &bytes.Buffer{}
			tp.mu.Lock()
			tp.streams = append(tp.streams, buf)
			tp.mu.Unlock()
			go func() {
				_, _ = io.Copy(io.MultiWriter(up, lockedWriter{&tp.mu, buf}), c)
				_ = up.Close()
			}()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
	return tp
}

func (tp *tap) addr() string { return tp.ln.Addr().String() }

// captured is what each dialer sent through the tap so far.
func (tp *tap) captured() [][]byte {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	out := make([][]byte, len(tp.streams))
	for i, b := range tp.streams {
		out[i] = bytes.Clone(b.Bytes())
	}
	return out
}

// replay sends each stream captured so far again, whole, on a new
// connection to the address, and returns them.
func (tp *tap) replay(t *testing.T) [][]byte {
	streams := tp.captured()
	for _, s := range streams {
		c, err := net.Dial("tcp", tp.address)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(s)
		t.Cleanup(func() { _ = c.Close() })
	}
	return streams
}

// interpose is the suite's Interpose: a tap whose replay is the suite's.
func interpose(t *testing.T, address string) (string, func()) {
	tp := newTap(t, address)
	return tp.addr(), func() { tp.replay(t) }
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

func harness(t *testing.T, tr *Transport, s transport.Shaping) transporttest.Harness {
	tg := theTarget(t)
	k := newKeys(t)
	return transporttest.Harness{
		Listen: func(t *testing.T, addr string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
			if addr == "" {
				addr = "127.0.0.1:0"
			}
			l, err := tr.Listen(t.Context(), transport.ListenConfig{Address: addr, Settings: listenSettingsFor(t, k, tg, 0)},
				transport.Admission{Peers: peers, Camouflage: camouflage})
			if err != nil {
				t.Fatal(err)
			}
			return l, transporttest.Endpoint{Address: l.Addr().String(), Settings: dialSettingsFor(t, k)}
		},
		Dialer:      tr.Dialer(),
		Credentials: shortIDs,
		Interpose:   interpose,
		Shaping:     s,
		Refused:     refused,
		Transport:   tr,
	}
}

// Shapings reality can't honour.
var refused = []transport.Shaping{
	{BatchWindow: time.Millisecond},
	{Jitter: time.Millisecond},
	{CoverInterval: time.Second},
	{Padding: transport.Padding{Mode: transport.PadRandom, Max: MaxRandomPadding + 1}},
	{Padding: transporttest.Buckets(1280, maxUnit+1)},
}
