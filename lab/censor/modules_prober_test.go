package censor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testCert is a self-signed certificate for name.
func testCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// listen starts a TCP server on 127.0.0.1 that serves each connection
// with serve, and returns its address.
func listen(t *testing.T, serve func(net.Conn)) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// webServer is an HTTPS server, the stand-in for nginx: cfg says its TLS.
func webServer(t *testing.T, cfg *tls.Config) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hello\n") }),
		ReadHeaderTimeout: time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return netip.MustParseAddrPort(ln.Addr().String())
}

func webTLS(t *testing.T, name string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{testCert(t, name)}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
}

// echo is a naive server: it sends back whatever it reads.
func echo(c net.Conn) {
	defer func() { _ = c.Close() }()
	_, _ = io.Copy(c, c)
}

// relay splices each connection to target, as an entry that forwards what
// it doesn't recognize to the real site does, a reset passed on as one;
// dialed runs on each dial.
func relay(target netip.AddrPort, dialed func()) func(net.Conn) {
	return func(c net.Conn) {
		defer func() { _ = c.Close() }()
		dialed()
		u, err := net.Dial("tcp", target.String())
		if err != nil {
			return
		}
		defer func() { _ = u.Close() }()
		go func() {
			_, _ = io.Copy(u, c)
			_ = u.(*net.TCPConn).CloseWrite()
		}()
		if _, err := io.Copy(c, u); errors.Is(err, syscall.ECONNRESET) {
			_ = c.(*net.TCPConn).SetLinger(0)
		}
	}
}

const siteName = "camouflage.example.net"

func newTestProber(t *testing.T, ref netip.AddrPort, extra string) *prober {
	t.Helper()
	settings := fmt.Sprintf(`{"reference": {"name": %q, "addresses": [%q]}, "timeout": "300ms"%s}`, siteName, ref, extra)
	m, err := newProber(json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	p := m.(*prober)
	p.grace = 50 * time.Millisecond
	return p
}

// runProber runs the prober's active half and returns its flows channel
// and the flags it raised.
func runProber(t *testing.T, p *prober) (chan<- FlowSnapshot, <-chan flagged) {
	t.Helper()
	flows := make(chan FlowSnapshot, 16)
	flags := make(chan flagged, 16)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Run(ctx, flows, func(k FlowKey, v Verdict, why string) { flags <- flagged{k, v, why} })
	return flows, flags
}

type flagged struct {
	key     FlowKey
	verdict Verdict
	why     string
}

func waitFlag(t *testing.T, flags <-chan flagged, key FlowKey) flagged {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case f := <-flags:
			if f.key == key {
				return f
			}
		case <-timeout:
			t.Fatalf("no flag of %s", key)
		}
	}
}

func suspectTo(server netip.AddrPort, sport uint16, payload []byte) FlowSnapshot {
	return FlowSnapshot{
		Key:     FlowKey{Proto: ProtoTCP, Src: netip.MustParseAddr("192.0.2.1"), Dst: server.Addr(), SrcPort: sport, DstPort: server.Port()},
		Payload: payload, Tagger: "prober", Tag: "tagged by fully-encrypted",
	}
}

// TestProberTellsEchoFromWebServer is the ticket's second check, with Go's
// HTTPS server as the web server: a server like the reference passes, a
// naive echo server is flagged, and each server is probed once.
func TestProberTellsEchoFromWebServer(t *testing.T) {
	ref := webServer(t, webTLS(t, siteName))
	same := webServer(t, webTLS(t, siteName))
	echoed := listen(t, echo)
	p := newTestProber(t, ref, "")
	flows, flags := runProber(t, p)
	random := randomBytes(6, 120)

	s := suspectTo(same, 40000, random)
	flows <- s
	if f := waitFlag(t, flags, s.Key); f.verdict != Accept || !strings.Contains(f.why, "answers like the reference") {
		t.Errorf("a web server like the reference: %+v", f)
	}

	s = suspectTo(echoed, 40001, random)
	flows <- s
	f := waitFlag(t, flags, s.Key)
	if f.verdict != Drop || !strings.Contains(f.why, "an echo") {
		t.Errorf("an echo server: %+v", f)
	}
	if back := waitFlag(t, flags, s.Key.Reverse()); back.verdict != Drop {
		t.Errorf("the echo server's replies: %+v", back)
	}
	// A second connection to the echo server is flagged without a probe,
	// and the passive half blocks every connection to it.
	s2 := suspectTo(echoed, 40002, random)
	flows <- s2
	if f := waitFlag(t, flags, s2.Key); f.verdict != Drop {
		t.Errorf("a second connection: %+v", f)
	}
	conn := tcpPacket(netip.MustParseAddr("192.0.2.9"), echoed.Addr(), 40003, echoed.Port(), 1, 0, Syn, nil)
	if d := p.Inspect(conn, &Flow{Key: FlowKey{ProtoTCP, conn.Src, conn.Dst, conn.SrcPort, conn.DstPort}}); d.Verdict != Drop || !d.Flow {
		t.Errorf("a new connection to the blocked server: %+v", d)
	}

	udp := FlowSnapshot{Key: FlowKey{Proto: ProtoUDP, Src: netip.MustParseAddr("192.0.2.1"), Dst: echoed.Addr(), SrcPort: 1, DstPort: 2}, Tagger: "prober"}
	flows <- udp
	if f := waitFlag(t, flags, udp.Key); f.verdict != Accept || !strings.Contains(f.why, "not probed") {
		t.Errorf("a UDP suspect: %+v", f)
	}

	s = suspectTo(ref, 40004, random)
	flows <- s
	if f := waitFlag(t, flags, s.Key); f.verdict != Accept || f.why != "not probed: the reference itself" {
		t.Errorf("a suspect connection to the reference: %+v", f)
	}
}

// TestConnEnd: failures alike compare alike, whatever the connection's
// addresses and ports.
func TestConnEnd(t *testing.T) {
	failure := func(local, remote string) error {
		return &net.OpError{
			Op: "read", Net: "tcp",
			Source: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(local)),
			Addr:   net.TCPAddrFromAddrPort(netip.MustParseAddrPort(remote)),
			Err:    os.NewSyscallError("read", syscall.EHOSTUNREACH),
		}
	}
	server, ref := connEnd(failure("192.0.2.1:40000", "203.0.113.9:443")), connEnd(failure("192.0.2.1:40001", "198.51.100.10:443"))
	if server != ref || server != "failed: "+syscall.EHOSTUNREACH.Error() {
		t.Errorf("the same failure: the server's %q, the reference's %q", server, ref)
	}
	for err, want := range map[error]string{
		io.EOF: "closed",
		fmt.Errorf("read: %w", syscall.ECONNRESET): "reset",
		os.ErrDeadlineExceeded:                     "open",
		errors.New("tls: something"):               "failed",
	} {
		if got := connEnd(err); got != want {
			t.Errorf("connEnd(%v) = %q, want %q", err, got, want)
		}
	}
}

// TestProberComparesTLS: a suspect whose ClientHello names the reference
// gets a TLS handshake of the censor's own, compared by JA3S, JA4S,
// extensions and negotiated ALPN; a server that negotiates other ALPN is
// flagged, a like one passes with the fingerprints in the verdict.
func TestProberComparesTLS(t *testing.T) {
	ref := webServer(t, webTLS(t, siteName))
	same := webServer(t, webTLS(t, siteName))
	h2cfg := webTLS(t, siteName)
	h2cfg.NextProtos = []string{"h2", "http/1.1"}
	h2 := webServer(t, h2cfg)
	p := newTestProber(t, ref, "")
	flows, flags := runProber(t, p)
	hello := helloFor(t, siteName)

	s := suspectTo(same, 40010, hello)
	flows <- s
	f := waitFlag(t, flags, s.Key)
	if f.verdict != Accept || !strings.Contains(f.why, "JA4S t13") || !strings.Contains(f.why, `negotiated ALPN "http/1.1"`) {
		t.Errorf("a like TLS server: %+v", f)
	}

	s = suspectTo(h2, 40011, hello)
	flows <- s
	if f := waitFlag(t, flags, s.Key); f.verdict != Drop || !strings.Contains(f.why, `negotiated ALPN "h2", the reference's "http/1.1"`) {
		t.Errorf("a server negotiating h2: %+v", f)
	}

	other := webServer(t, webTLS(t, siteName))
	s = suspectTo(other, 40012, helloFor(t, "elsewhere.example.net"))
	flows <- s
	if f := waitFlag(t, flags, s.Key); !strings.Contains(f.why, "TLS: not compared") {
		t.Errorf("a ClientHello naming another site: %+v", f)
	}
}

// TestProberUpstreamTell: an entry that relays each probe to the
// reference answers like the reference, and is flagged only for the
// connection it opens to the reference on every probe, which the censor
// sees only from a vantage on the entry's uplink.
func TestProberUpstreamTell(t *testing.T) {
	ref := webServer(t, webTLS(t, siteName))
	for _, seen := range []bool{true, false} {
		p := newTestProber(t, ref, `, "upstreamTell": "flag"`)
		flows, flags := runProber(t, p)
		var entry netip.AddrPort
		entry = listen(t, relay(ref, func() {
			// Unseen, the censor still sees other hosts connect to the
			// site, which say nothing about the entry.
			src := netip.MustParseAddr("192.0.2.77")
			if seen {
				src = entry.Addr()
			}
			flows <- FlowSnapshot{Key: FlowKey{Proto: ProtoTCP, Src: src, Dst: ref.Addr(), SrcPort: 50000, DstPort: ref.Port()}, Started: time.Now()}
		}))
		s := suspectTo(entry, 40020, helloFor(t, siteName))
		flows <- s
		f := waitFlag(t, flags, s.Key)
		switch {
		case seen && (f.verdict != Drop || !strings.Contains(f.why, "upstream tell: a connection") ||
			strings.Contains(f.why, ": the server ") || strings.Contains(f.why, "TLS:")):
			t.Errorf("a relay whose uplink the censor sees: %+v", f)
		case !seen && f.verdict != Accept:
			t.Errorf("a relay whose uplink the censor doesn't see: %+v", f)
		}
	}
}

// TestProberReportsUpstreamTell: with upstreamTell "report", a relay whose
// uplink the censor sees passes, and the verdict says it showed the tell.
func TestProberReportsUpstreamTell(t *testing.T) {
	ref := webServer(t, webTLS(t, siteName))
	p := newTestProber(t, ref, `, "upstreamTell": "report"`)
	flows, flags := runProber(t, p)
	var entry netip.AddrPort
	entry = listen(t, relay(ref, func() {
		flows <- FlowSnapshot{Key: FlowKey{Proto: ProtoTCP, Src: entry.Addr(), Dst: ref.Addr(), SrcPort: 50000, DstPort: ref.Port()}, Started: time.Now()}
	}))
	s := suspectTo(entry, 40025, helloFor(t, siteName))
	flows <- s
	if f := waitFlag(t, flags, s.Key); f.verdict != Accept || !strings.Contains(f.why, "upstream tell: a connection") || !strings.Contains(f.why, "reported, not flagged") {
		t.Errorf("a relay, the tell reported: %+v", f)
	}
}

// TestProberTagsListedDestinations: with destinations, the passive half
// tags a client's TCP flow to one once it has sent data, and nothing
// else.
func TestProberTagsListedDestinations(t *testing.T) {
	p := newTestProber(t, netip.MustParseAddrPort("198.51.100.10:443"), `, "destinations": ["203.0.113.0/24"]`)
	var tagged []string
	eng := NewEngine([]Passive{&tagRecorder{inner: p, tags: &tagged}}, nil, nil)
	seq := handshake(eng)
	if len(tagged) != 0 {
		t.Errorf("tagged before data: %v", tagged)
	}
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, []byte("x")))
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5001, seq+1, Ack|Psh, []byte("y")))
	if len(tagged) != 1 || !strings.Contains(tagged[0], "tcp 192.0.2.1:40000->203.0.113.9:443") {
		t.Errorf("tags %v, want the client's flow once", tagged)
	}
	elsewhere := netip.MustParseAddr("198.51.100.2")
	eng.Handle(tcpPacket(clientAddr, elsewhere, 40001, 443, 1, 0, Syn, nil))
	eng.Handle(tcpPacket(elsewhere, clientAddr, 443, 40001, 9, 2, Syn|Ack, nil))
	eng.Handle(tcpPacket(clientAddr, elsewhere, 40001, 443, 2, 10, Ack|Psh, []byte("x")))
	if len(tagged) != 1 {
		t.Errorf("tagged an unlisted destination: %v", tagged)
	}
}

// TestProberWaitsForTheWholeHello: a ClientHello with a post-quantum key
// share spans two segments; the prober tags the flow only once all of it
// is in, so the replay probe sends the whole hello and the TLS comparison
// runs.
func TestProberWaitsForTheWholeHello(t *testing.T) {
	ref := webServer(t, webTLS(t, siteName))
	same := webServer(t, webTLS(t, siteName))
	hello := helloFor(t, siteName)
	// crypto/tls's default key shares include X25519MLKEM768's 1216 bytes,
	// as Chrome's and uTLS's do.
	if len(hello) < 1400 {
		t.Fatalf("a %d-byte ClientHello: want one with a post-quantum key share", len(hello))
	}
	p := newTestProber(t, ref, fmt.Sprintf(`, "destinations": ["%s/32"]`, same.Addr()))
	var log syncBuffer
	eng := NewEngine([]Passive{p}, []Active{p}, &log)
	t.Cleanup(eng.Shutdown)
	client, srv, port := netip.MustParseAddr("127.0.0.2"), same.Addr(), same.Port()
	eng.Handle(tcpPacket(client, srv, 40000, port, 1000, 0, Syn, nil))
	eng.Handle(tcpPacket(srv, client, port, 40000, 5000, 1001, Syn|Ack, nil))
	split := 1000
	eng.Handle(tcpPacket(client, srv, 40000, port, 1001, 5001, Ack|Psh, hello[:split]))
	if strings.Contains(log.String(), `"event":"tag"`) {
		t.Fatalf("tagged on half a ClientHello:\n%s", log.String())
	}
	eng.Handle(tcpPacket(client, srv, 40000, port, 1001+uint32(split), 5001, Ack|Psh, hello[split:]))
	waitLog(t, &log, `"event":"flag"`)
	for _, want := range []string{"answers like the reference", "TLS: the server", "replay: answered a TLS handshake"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("the verdict doesn't say %q:\n%s", want, log.String())
		}
	}
}

// tagRecorder records the tags of the module it wraps.
type tagRecorder struct {
	inner Passive
	tags  *[]string
}

func (r *tagRecorder) Name() string { return r.inner.Name() }

func (r *tagRecorder) Inspect(p *Packet, f *Flow) Decision {
	d := r.inner.Inspect(p, f)
	if d.Tag != "" {
		*r.tags = append(*r.tags, f.Key.String())
	}
	return d
}

// TestProberOnTheEngine runs fully-encrypted, tag only, and the prober
// through the engine: a random stream to an echo server is tagged, probed,
// and dropped from a later packet on, both ways.
func TestProberOnTheEngine(t *testing.T) {
	ref := webServer(t, webTLS(t, siteName))
	echoed := listen(t, echo)
	fe, err := newFullyEncrypted([]byte(`{"tagOnly": true}`))
	if err != nil {
		t.Fatal(err)
	}
	p := newTestProber(t, ref, "")
	eng := NewEngine([]Passive{fe, p}, []Active{p}, nil)
	t.Cleanup(eng.Shutdown)
	client := netip.MustParseAddr("127.0.0.2")
	srv, port := echoed.Addr(), echoed.Port()
	eng.Handle(tcpPacket(client, srv, 40000, port, 1000, 0, Syn, nil))
	eng.Handle(tcpPacket(srv, client, port, 40000, 5000, 1001, Syn|Ack, nil))
	random := randomBytes(7, 200)
	if a := eng.Handle(tcpPacket(client, srv, 40000, port, 1001, 5001, Ack|Psh, random)); a.Verdict != Accept {
		t.Fatalf("the first data, tag only: %+v", a)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		a := eng.Handle(tcpPacket(client, srv, 40000, port, 1201, 5001, Ack, nil))
		if a.Verdict == Drop && a.Module == "prober" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never dropped: %+v", a)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if a := eng.Handle(tcpPacket(srv, client, port, 40000, 5001, 1201, Ack|Psh, random)); a.Verdict != Drop {
		t.Errorf("the server's direction: %+v", a)
	}
}

func TestProberSettings(t *testing.T) {
	for name, settings := range map[string]string{
		"no reference":      `{}`,
		"no name":           `{"reference": {"addresses": ["198.51.100.10:443"]}}`,
		"bad address":       `{"reference": {"name": "a.example.net", "addresses": ["198.51.100.10"]}}`,
		"bad destination":   `{"reference": {"name": "a.example.net", "addresses": ["198.51.100.10:443"]}, "destinations": ["x"]}`,
		"bad timeout":       `{"reference": {"name": "a.example.net", "addresses": ["198.51.100.10:443"]}, "timeout": "-1s"}`,
		"bad verdict":       `{"reference": {"name": "a.example.net", "addresses": ["198.51.100.10:443"]}, "verdict": "poison"}`,
		"bad upstream tell": `{"reference": {"name": "a.example.net", "addresses": ["198.51.100.10:443"]}, "upstreamTell": "ignore"}`,
	} {
		if _, err := newProber(json.RawMessage(settings)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
