package reality

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The host-side lab test (prototype_test.go, lab build tag) starts the lab
// and the stock Xray container, writes this config into the node, and runs
// the package's tests inside it. Without both, skip.
const inNodeConfigPath = "/run/reality-prototype/config.json"

type inNodeConfig struct {
	XrayAddr      string `json:"xray_addr"`       // the stock Xray server, ip:port
	SNI           string `json:"sni"`             // e.g. example.net
	ServerKey     string `json:"server_key"`      // listener's static X25519 public key, base64url raw
	ShortID       string `json:"short_id"`        // hex, 16 digits
	ShortIDWrong  string `json:"short_id_wrong"`  // hex, not accepted by the server
	UserID        string `json:"user_id"`         // VLESS user UUID
	HTTPAddr      string `json:"http_addr"`       // the echo server, ip:port, as Xray dials it
	XrayVersion   string `json:"xray_version"`    // e.g. 26.3.27
	TargetTLSAddr string `json:"target_tls_addr"` // the camouflage target, ip:port, as Xray dials it
}

const echoBody = "thinkpol tp-064 prototype echo\n"

func TestRealityClientInterop(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	raw, err := os.ReadFile(inNodeConfigPath)
	if err != nil {
		t.Skipf("no prototype config in this node: %v", err)
	}
	var cfg inNodeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config: %v", err)
	}

	serverKey, err := base64.RawURLEncoding.DecodeString(cfg.ServerKey)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	shortID, err := hex.DecodeString(cfg.ShortID)
	if err != nil {
		t.Fatalf("short id: %v", err)
	}
	shortIDWrong, err := hex.DecodeString(cfg.ShortIDWrong)
	if err != nil {
		t.Fatalf("wrong short id: %v", err)
	}
	var version [3]byte
	if n, err := fmt.Sscanf(cfg.XrayVersion, "%d.%d.%d", &version[0], &version[1], &version[2]); err != nil || n != 3 {
		t.Fatalf("xray version %q: %v", cfg.XrayVersion, err)
	}

	startTarget(t, cfg.TargetTLSAddr, cfg.SNI)
	startEcho(t, cfg.HTTPAddr)

	t.Run("right short id", func(t *testing.T) {
		resetTargetStats()
		client := handshake(t, cfg.XrayAddr, ClientConfig{
			ServerName:      cfg.SNI,
			ServerPublicKey: serverKey,
			ShortID:         shortID,
			Version:         version,
		}, authenticates)

		// The seal was accepted: the server keyed it from the standalone
		// X25519 share the Chrome hello carries (the client prefers it over
		// the X25519MLKEM768 half).
		if client.conn.HandshakeState.State13.KeyShareKeys.Ecdhe == nil {
			t.Error("the handshake was keyed from the X25519MLKEM768 half, not the standalone X25519 share")
		}

		// One application-data round trip: a single VLESS request to the
		// echo server, through the stock Xray inbound.
		var userID [16]byte
		uid, err := hex.DecodeString(strings.ReplaceAll(cfg.UserID, "-", ""))
		if err != nil || len(uid) != 16 {
			t.Fatalf("user id: %v", err)
		}
		copy(userID[:], uid)
		httpAddr, err := netip.ParseAddrPort(cfg.HTTPAddr)
		if err != nil {
			t.Fatalf("http addr: %v", err)
		}
		request := VLESSRequest(userID, httpAddr.Addr(), httpAddr.Port(),
			[]byte("GET /tp064 HTTP/1.1\r\nHost: "+cfg.SNI+"\r\nConnection: close\r\n\r\n"))
		if _, err := client.Write(request); err != nil {
			t.Fatalf("write VLESS request: %v", err)
		}
		if err := VLESSResponse(client); err != nil {
			t.Fatalf("VLESS response header: %v", err)
		}
		// The request asks the server to close, so the response ends at EOF.
		response, err := io.ReadAll(client)
		if err != nil {
			t.Fatalf("read echo response: %v", err)
		}
		if !bytes.HasSuffix(response, []byte(echoBody)) {
			t.Fatalf("echo response: got %q, want it to end with %q", response, echoBody)
		}

		// Measured, not assumed: on the authenticated path Xray has already
		// dialed the camouflage target; what reaches it there decides the
		// upstream tell (TP-087, TP-088). A short settle lets anything Xray
		// had in flight land.
		time.Sleep(500 * time.Millisecond)
		conns, hellos := targetStats()
		t.Logf("authenticated path: the target accepted %d connection(s), %d carried a ClientHello", conns, len(hellos))
		for i, h := range hellos {
			if bytes.Equal(h, client.Hello) {
				t.Logf("authenticated path: hello %d/%d is byte-identical to what the client sent", i+1, len(hellos))
			} else {
				t.Logf("authenticated path: hello %d/%d differs from what the client sent", i+1, len(hellos))
			}
		}
	})

	t.Run("wrong short id", func(t *testing.T) {
		resetTargetStats()
		handshake(t, cfg.XrayAddr, ClientConfig{
			ServerName:      cfg.SNI,
			ServerPublicKey: serverKey,
			ShortID:         shortIDWrong,
			Version:         version,
		}, splices)
	})

	// The seal carries a Unix time the server checks against maxTimeDiff.
	// The config sets it to 10000: read as milliseconds (as Xray's conf
	// reads it), the window is 10 s and a 60 s skew is stale; read as
	// seconds, the window is ~2.8 h and the handshake would authenticate.
	t.Run("stale timestamp", func(t *testing.T) {
		resetTargetStats()
		timeNow = func() time.Time { return time.Now().Add(-time.Minute) }
		defer func() { timeNow = time.Now }()
		handshake(t, cfg.XrayAddr, ClientConfig{
			ServerName:      cfg.SNI,
			ServerPublicKey: serverKey,
			ShortID:         shortID,
			Version:         version,
		}, splices)
	})
}

// outcome says which server behaviour a handshake should produce.
type outcome uint

const (
	authenticates outcome = iota // the server accepted the seal: a REALITY session
	splices                      // the server rejected it: the connection is spliced to the target
)

// handshake runs one REALITY handshake against the stock server. want says
// which outcome the caller expects; the checks for the splice path run here.
func handshake(t *testing.T, addr string, cfg ClientConfig, want outcome) *Client {
	t.Helper()
	dialed, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	client, err := NewClient(dialed, cfg)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handshakeErr := client.Handshake(ctx)

	switch want {
	case authenticates:
		if handshakeErr != nil {
			t.Fatalf("REALITY handshake: %v", handshakeErr)
		}
	case splices:
		if handshakeErr == nil {
			t.Fatal("expected the splice path (real certificate), got a REALITY session")
		}
		if !errors.Is(handshakeErr, errRealCertificate) {
			t.Fatalf("expected the splice path, got: %v", handshakeErr)
		}
		certs := client.PeerCertificates()
		if len(certs) == 0 {
			t.Fatal("splice path: no certificate presented")
		}
		if !certs[0].Equal(targetLeaf()) {
			t.Fatal("splice path: the leaf is not the local target's certificate")
		}
		sent := capturedHello()
		if !bytes.Equal(sent, client.Hello) {
			t.Fatalf("splice path: the target saw a different ClientHello:\n got %x\nwant %x", sent, client.Hello)
		}
		t.Logf("splice path: the target received the identical ClientHello (%d bytes)", len(client.Hello))
	}
	return client
}

// The camouflage target and the echo server run in this test binary. One
// test runs at a time in the node, so package-level state is fine.
var (
	targetMu       sync.Mutex
	targetLeafCert *tls.Certificate
	targetParsed   *x509.Certificate
	targetConns    int      // connections accepted since the last resetTargetStats
	targetHellos   [][]byte // the first ClientHello record on each connection that delivered one
)

// resetTargetStats makes the connection and hello counts measure one
// subtest only.
func resetTargetStats() {
	targetMu.Lock()
	defer targetMu.Unlock()
	targetConns, targetHellos = 0, nil
}

// targetStats reports how many connections the target accepted since the
// last reset, and the ClientHello messages captured on them (the
// handshake-message bytes, record header stripped).
func targetStats() (conns int, hellos [][]byte) {
	targetMu.Lock()
	defer targetMu.Unlock()
	return targetConns, append([][]byte(nil), targetHellos...)
}

func startTarget(t *testing.T, addr, sni string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("mint target key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sni},
		DNSNames:     []string{sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("mint target certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse target certificate: %v", err)
	}
	targetMu.Lock()
	targetLeafCert, targetParsed = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, parsed
	targetMu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("target listen %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			targetMu.Lock()
			targetConns++
			targetMu.Unlock()
			go func() {
				defer func() { _ = conn.Close() }()
				tlsConn := tls.Server(&recordingConn{Conn: conn}, &tls.Config{
					Certificates: []tls.Certificate{*targetLeafCert},
					MinVersion:   tls.VersionTLS13,
				})
				// Xray splices the raw bytes to us when the seal is
				// rejected; on the authenticated path it also forwards the
				// ClientHello (measured, see the right-short-id subtest's
				// log) but nothing else, so the handshake times out and the
				// connection is dropped. Both are fine.
				_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				_ = tlsConn.SetDeadline(time.Time{})
				_, _ = io.Copy(io.Discard, tlsConn)
			}()
		}
	}()
}

func targetLeaf() *x509.Certificate {
	targetMu.Lock()
	defer targetMu.Unlock()
	return targetParsed
}

func capturedHello() []byte {
	targetMu.Lock()
	defer targetMu.Unlock()
	if len(targetHellos) == 0 {
		return nil
	}
	return append([]byte(nil), targetHellos[0]...)
}

// recordingConn keeps the first complete TLS record a connection delivers:
// the ClientHello record Xray forwarded untouched.
type recordingConn struct {
	net.Conn
	buf  []byte
	done bool
	mu   sync.Mutex
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return n, err
	}
	c.buf = append(c.buf, p[:n]...)
	if len(c.buf) >= 5 {
		if l := int(c.buf[3])<<8 | int(c.buf[4]); len(c.buf) >= 5+l {
			targetMu.Lock()
			targetHellos = append(targetHellos, append([]byte(nil), c.buf[5:5+l]...))
			targetMu.Unlock()
			c.done = true
		}
	}
	return n, err
}

func startEcho(t *testing.T, addr string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/tp064", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(echoBody))
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("echo listen %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(ln) }()
}
