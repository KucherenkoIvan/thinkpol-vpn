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
	"slices"
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
// input after the handshake. A connection idle for its idle timeout is
// closed; with halfClose, a connection whose handshake failed is closed
// for writing only, the target reading on until the far end closes.
type target struct {
	ln        net.Listener
	cert      *x509.Certificate
	idle      time.Duration
	halfClose bool

	mu    sync.Mutex
	conns []*recorder
}

var (
	sharedTarget     *target
	sharedTargetErr  error
	sharedTargetOnce sync.Once
)

// theTarget is one target for the whole test binary: REALITY learns a
// target's records once per process.
func theTarget(t testing.TB) *target {
	t.Helper()
	sharedTargetOnce.Do(func() { sharedTarget, sharedTargetErr = startTarget("127.0.0.1:0", 10*time.Second, false) })
	if sharedTargetErr != nil {
		t.Fatal(sharedTargetErr)
	}
	return sharedTarget
}

// newTargetAt starts a target listening on address.
func newTargetAt(t testing.TB, address string) *target {
	t.Helper()
	tg, err := startTarget(address, 10*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tg.ln.Close() })
	return tg
}

// newIdleTarget starts a target on loopback whose connections end after
// idle, as halfClose says.
func newIdleTarget(t testing.TB, idle time.Duration, halfClose bool) *target {
	t.Helper()
	tg, err := startTarget("127.0.0.1:0", idle, halfClose)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tg.ln.Close() })
	return tg
}

func startTarget(address string, idle time.Duration, halfClose bool) (*target, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	tg := &target{ln: ln, cert: cert, idle: idle, halfClose: halfClose}
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
	return tg, nil
}

func (tg *target) serve(c net.Conn, cfg *tls.Config) {
	rec := &recorder{Conn: c, done: make(chan struct{})}
	defer func() {
		_ = c.Close()
		close(rec.done)
	}()
	_ = c.SetDeadline(time.Now().Add(tg.idle))
	tg.mu.Lock()
	tg.conns = append(tg.conns, rec)
	tg.mu.Unlock()
	tc := tls.Server(rec, cfg)
	if err := tc.Handshake(); err != nil {
		if tg.halfClose {
			_ = c.(*net.TCPConn).CloseWrite()
			_ = c.SetDeadline(time.Time{})
		}
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

// connWith waits for a connection to the target to have sent it exactly
// stream, and returns it, or nil.
func (tg *target) connWith(stream []byte) *recorder {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tg.mu.Lock()
		conns := slices.Clone(tg.conns)
		tg.mu.Unlock()
		for _, r := range conns {
			if bytes.Equal(r.bytes(), stream) {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// recorder keeps what was read from a connection.
type recorder struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	done chan struct{} // closed once the target is done with the connection
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
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{k.Bytes(), k.PublicKey().Bytes()}
}

func mustMarshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listenSettingsFor(t testing.TB, k keys, tg *target, window uint32) []byte {
	t.Helper()
	return mustMarshal(t, &transportv1.RealityListenSettings{
		PrivateKey: k.private, Target: tg.addr(), ServerNames: []string{serverName}, TimeWindowS: window,
	})
}

func dialSettingsFor(t testing.TB, k keys) []byte {
	t.Helper()
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
	t.Helper()
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
	t.Helper()
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
	t.Helper()
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
	t.Helper()
	tg := theTarget(t)
	k := newKeys(t)
	return transporttest.Harness{
		Listen: func(t *testing.T, addr string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
			t.Helper()
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
