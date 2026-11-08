package censor

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a verdict log a test reads while the engine writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// firstFlight is what server sends first in answer to hello, up to and
// including its whole ServerHello.
func firstFlight(t *testing.T, server netip.AddrPort, hello []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	var got []byte
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if _, herr := serverHelloOf(got); herr == nil {
			return got
		}
		if err != nil {
			t.Fatalf("%s answered %d bytes and no ServerHello: %v", server, len(got), err)
		}
	}
}

// helloALPN is the ClientHello crypto/tls sends for name offering ALPN h2
// and http/1.1.
func helloALPN(t *testing.T, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: name, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}).Handshake()
		_ = c.Close()
	}()
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	buf := make([]byte, 4096)
	for {
		n, err := s.Read(buf)
		got = append(got, buf[:n]...)
		if _, used, herr := helloMessage(got, tlsClientHello); herr == nil {
			return got[:used]
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// helloConnection runs a TLS connection's start through the engine: the
// handshake, the client's hello and the server's first flight, and
// returns the client's and the server's next sequence numbers.
func helloConnection(eng *Engine, sport uint16, hello, flight []byte) (uint32, uint32) {
	eng.Handle(tcpPacket(clientAddr, serverAddr, sport, 443, 1000, 0, Syn, nil))
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, sport, 5000, 1001, Syn|Ack, nil))
	eng.Handle(tcpPacket(clientAddr, serverAddr, sport, 443, 1001, 5001, Ack, nil))
	cseq := 1001 + uint32(len(hello))
	eng.Handle(tcpPacket(clientAddr, serverAddr, sport, 443, 1001, 5001, Ack|Psh, hello))
	sseq := 5001 + uint32(len(flight))
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, sport, 5001, cseq, Ack|Psh, flight))
	return cseq, sseq
}

func waitLog(t *testing.T, log *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(log.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in the verdict log:\n%s", want, log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServerHelloComparesWithTheSite: a server answering a ClientHello for
// a listed site as the site does passes, with its fingerprints in the
// verdict log; one whose hello differs (TLS 1.2 with ALPN, where the site
// speaks TLS 1.3) is dropped both ways, and later connections to it are
// too; a ClientHello for an unlisted name isn't compared.
func TestServerHelloComparesWithTheSite(t *testing.T) {
	site := webServer(t, webTLS(t, siteName))
	like := webServer(t, webTLS(t, siteName))
	oldCfg := webTLS(t, siteName)
	oldCfg.MaxVersion, oldCfg.NextProtos = tls.VersionTLS12, []string{"h2"}
	old := webServer(t, oldCfg)
	hello := helloALPN(t, siteName)

	var log syncBuffer
	m, err := newServerHelloCheck(json.RawMessage(fmt.Sprintf(`{"sites": {%q: %q}}`, strings.ToUpper(siteName), site)))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine([]Passive{m}, []Active{m.(Active)}, &log)
	t.Cleanup(eng.Shutdown)

	helloConnection(eng, 40000, hello, firstFlight(t, like, hello))
	waitLog(t, &log, "server hello matches the site "+site.String())
	waitLog(t, &log, `"event":"tag","flow":"tcp 203.0.113.9:443->192.0.2.1:40000"`)

	cseq, sseq := helloConnection(eng, 40001, hello, firstFlight(t, old, hello))
	waitLog(t, &log, "server hello unlike the site")
	for _, want := range []string{"version 0x0303", "ALPN \\\"h2\\\", the site's \\\"\\\"", "JA4S t12"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("the verdict log doesn't say %s:\n%s", want, log.String())
		}
	}
	if a := eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40001, sseq, cseq, Ack|Psh, []byte("x"))); a.Verdict != Drop || a.Module != "server-hello" {
		t.Errorf("the server's next packet: %+v", a)
	}
	if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40001, 443, cseq, sseq, Ack|Psh, []byte("x"))); a.Verdict != Drop {
		t.Errorf("the client's next packet: %+v", a)
	}
	if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40002, 443, 1, 0, Syn, nil)); a.Verdict != Drop {
		t.Errorf("a new connection to the server found out: %+v", a)
	}

	other := helloFor(t, "elsewhere.example.net")
	helloConnection(eng, 40003, other, firstFlight(t, like, other))
	time.Sleep(200 * time.Millisecond)
	if strings.Contains(log.String(), "server hello for elsewhere.example.net") {
		t.Errorf("a hello for an unlisted name was compared:\n%s", log.String())
	}
}
