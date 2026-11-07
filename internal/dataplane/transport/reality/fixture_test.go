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
// records the first bytes of every connection, and answers "site" to a
// line of input after the handshake.
type target struct {
	ln   net.Listener
	cert *x509.Certificate

	mu     sync.Mutex
	starts [][]byte // each connection's first bytes, up to the ClientHello
	conns  int
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

func newTarget(t testing.TB) *target {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	rec := &recorder{Conn: c}
	tc := tls.Server(rec, cfg)
	err := tc.Handshake()
	tg.mu.Lock()
	tg.conns++
	tg.starts = append(tg.starts, rec.first())
	tg.mu.Unlock()
	if err != nil {
		return
	}
	buf := make([]byte, 64)
	if _, err := tc.Read(buf); err == nil {
		_, _ = tc.Write([]byte("site"))
	}
}

func (tg *target) addr() string { return tg.ln.Addr().String() }

// seen reports the starts of the connections the target has had so far.
func (tg *target) seen() [][]byte {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([][]byte(nil), tg.starts...)
}

// recorder keeps the first bytes read from a connection.
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

func (r *recorder) first() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) >= recordHeaderSize {
		if n := recordHeaderSize + int(r.buf[3])<<8 | int(r.buf[4]); n <= len(r.buf) {
			return bytes.Clone(r.buf[:n])
		}
	}
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

// interpose puts a TCP tap in front of address for the suite's Replay
// test: replay sends each connection's client bytes again, whole, on a new
// connection.
func interpose(t *testing.T, address string) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var captured []*bytes.Buffer
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
			mu.Lock()
			captured = append(captured, buf)
			mu.Unlock()
			go func() {
				_, _ = io.Copy(io.MultiWriter(up, lockedWriter{&mu, buf}), c)
				_ = up.Close()
			}()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
	return ln.Addr().String(), func() {
		mu.Lock()
		streams := make([][]byte, len(captured))
		for i, b := range captured {
			streams[i] = bytes.Clone(b.Bytes())
		}
		mu.Unlock()
		for _, s := range streams {
			c, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = c.Write(s)
			t.Cleanup(func() { _ = c.Close() })
		}
	}
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
