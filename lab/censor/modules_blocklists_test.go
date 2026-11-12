package censor

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func buildPassive(t *testing.T, name, settings string) Passive {
	t.Helper()
	ps, _, err := Build(Config{Modules: []ModuleConfig{{Name: name, Settings: []byte(settings)}}})
	if err != nil {
		t.Fatal(err)
	}
	return ps[0]
}

// TestIPBlocklistEitherEnd: a listed address blocks a packet to it and
// from it, a listed network blocks every address in it, both families,
// and everything else passes, the module retiring from the flow.
func TestIPBlocklistEitherEnd(t *testing.T) {
	m := buildPassive(t, "ip-blocklist", `{"addresses": ["203.0.113.9", "198.51.100.0/24", "2001:db8:1::/48"]}`)
	other := netip.MustParseAddr("192.0.2.1")
	for _, listed := range []string{"203.0.113.9", "198.51.100.77", "2001:db8:1:2::3"} {
		a := netip.MustParseAddr(listed)
		peer := other
		if a.Is6() {
			peer = netip.MustParseAddr("2001:db8:2::1")
		}
		for _, p := range []*Packet{udpPacket(peer, a, 1, 2, []byte("x")), udpPacket(a, peer, 2, 1, []byte("x"))} {
			if d := m.Inspect(p, &Flow{}); d.Verdict != Drop || !d.Flow || !strings.Contains(d.Reason, listed) {
				t.Errorf("%s: %+v", p, d)
			}
		}
	}
	for _, free := range []string{"203.0.113.10", "198.51.101.1", "2001:db8:2::9", "::ffff:203.0.113.9"} {
		a := netip.MustParseAddr(free)
		peer := other
		if a.Is6() {
			peer = netip.MustParseAddr("2001:db8:2::1")
		}
		if d := m.Inspect(udpPacket(peer, a, 1, 2, nil), &Flow{}); d != retired {
			t.Errorf("%s isn't listed: %+v", free, d)
		}
	}
}

// TestIPBlocklistSettings: a list is required, verdicts are drop, reset
// and throttle with its rate.
func TestIPBlocklistSettings(t *testing.T) {
	for settings, wantErr := range map[string]string{
		`{}`:                                   "no address listed",
		`{"addresses": ["203.0.113.0/33"]}`:    `address "203.0.113.0/33"`,
		`{"addresses": ["x"], "verdict": "x"}`: `address "x"`,
		`{"addresses": ["203.0.113.9"], "verdict": "poison"}`:   "verdict",
		`{"addresses": ["203.0.113.9"], "rate": -1}`:            "rate",
		`{"addresses": ["203.0.113.9"], "verdict": "reset"}`:    "",
		`{"addresses": ["203.0.113.9"], "verdict": "throttle"}`: "",
	} {
		_, err := newIPBlocklist([]byte(settings))
		if wantErr == "" && err != nil || wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)) {
			t.Errorf("%s: err %v, want %q", settings, err, wantErr)
		}
	}
	m := buildPassive(t, "ip-blocklist", `{"addresses": ["203.0.113.9"], "verdict": "throttle", "rate": 500}`)
	d := m.Inspect(udpPacket(clientAddr, serverAddr, 1, 2, nil), &Flow{})
	if d.Verdict != Throttle || d.Rate != 500 {
		t.Errorf("throttle: %+v", d)
	}
}

// helloFor is the ClientHello crypto/tls sends for name ("" for none).
func helloFor(t *testing.T, name string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: name == ""}).Handshake()
		_ = c.Close()
	}()
	defer func() { _ = s.Close() }()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(s, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// splitRecords re-frames a one-record ClientHello into records of at most
// n bytes of handshake data each, as a record-fragmenting client sends it.
func splitRecords(hello []byte, n int) []byte {
	var out []byte
	for body := hello[tlsRecordHeader:]; len(body) > 0; {
		k := min(n, len(body))
		out = append(out, hello[0], hello[1], hello[2], byte(k>>8), byte(k))
		out = append(out, body[:k]...)
		body = body[k:]
	}
	return out
}

// TestClientHelloServerName reads the name of a real ClientHello, whole
// and split over records of a few bytes, says incomplete for every
// shorter prefix of either, and tells what isn't a ClientHello.
func TestClientHelloServerName(t *testing.T) {
	hello := helloFor(t, "www.example.net")
	for name, b := range map[string][]byte{"one record": hello, "records of 7 bytes": splitRecords(hello, 7)} {
		if got, err := clientHelloServerName(b); err != nil || got != "www.example.net" {
			t.Errorf("%s: %q, %v", name, got, err)
		}
		for i := 0; i < len(b); i++ {
			if _, err := clientHelloServerName(b[:i]); err != errIncomplete {
				t.Fatalf("%s: a %d-byte prefix of %d: %v, want incomplete", name, i, len(b), err)
			}
		}
		// Bytes after the ClientHello (early data, say) change nothing.
		if got, err := clientHelloServerName(append(bytes.Clone(b), 23, 3, 3, 0, 1, 0)); err != nil || got != "www.example.net" {
			t.Errorf("%s with a record after it: %q, %v", name, got, err)
		}
	}
	if got, err := clientHelloServerName(helloFor(t, "")); err != nil || got != "" {
		t.Errorf("no server name: %q, %v", got, err)
	}

	serverHello := bytes.Clone(hello)
	serverHello[5] = 2
	appData := bytes.Clone(hello)
	appData[0] = 23
	truncatedBody := bytes.Clone(hello)
	binary.BigEndian.PutUint16(truncatedBody[3:], uint16(len(hello)-5-10))
	truncatedBody = truncatedBody[:len(hello)-10] // the record ends where the message says it doesn't
	for name, b := range map[string][]byte{
		"http":          []byte("GET / HTTP/1.1\r\nHost: www.example.net\r\n\r\n"),
		"server hello":  serverHello,
		"not handshake": appData,
		"empty record":  {22, 3, 1, 0, 0},
	} {
		if _, err := clientHelloServerName(b); err != errNotClientHello {
			t.Errorf("%s: %v, want not a ClientHello", name, err)
		}
	}
	// A ClientHello longer than the censor keeps is one, never whole.
	if _, err := clientHelloServerName([]byte{22, 3, 1, 0, 4, 1, 0xff, 0, 0}); err != errHelloTooLong {
		t.Errorf("a ClientHello longer than retainBytes: %v, want too long", err)
	}
	// A record that ends mid-message waits for the next.
	if _, err := clientHelloServerName(truncatedBody); err != errIncomplete {
		t.Errorf("a record ending mid-message: %v", err)
	}
}

// TestSNIBlocklistSplitClientHello: a ClientHello for a listed name split
// over two segments, in order or not, and over TLS records too, passes
// until it is whole and is reset by the packet completing it; the
// connection stays reset.
func TestSNIBlocklistSplitClientHello(t *testing.T) {
	m := buildPassive(t, "sni-blocklist", `{"names": ["Example.NET."]}`)
	for name, hello := range map[string][]byte{
		"one record":  helloFor(t, "www.example.net"),
		"two records": splitRecords(helloFor(t, "www.example.net"), 60),
	} {
		at := bytes.Index(hello, []byte("example.net"))
		for _, reversed := range []bool{false, true} {
			eng := NewEngine([]Passive{m}, nil, nil)
			seq := handshake(eng)
			first := tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack, hello[:at+3])
			second := tcpPacket(clientAddr, serverAddr, 40000, 443, seq+uint32(at+3), 5001, Ack|Psh, hello[at+3:])
			if reversed {
				first, second = second, first
			}
			if a := eng.Handle(first); a.Verdict != Accept {
				t.Errorf("%s, reversed %v: the first segment: %+v", name, reversed, a)
			}
			a := eng.Handle(second)
			if a.Verdict != Reset || a.Module != "sni-blocklist" || !strings.Contains(a.Reason, "www.example.net listed as example.net") {
				t.Errorf("%s, reversed %v: the completing segment: %+v", name, reversed, a)
			}
			if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq+uint32(len(hello)), 5001, Ack, []byte("x"))); a.Verdict != Reset {
				t.Errorf("%s, reversed %v: after the reset: %+v", name, reversed, a)
			}
		}
	}
}

// TestSNIBlocklistPasses: an unlisted name, a name that only ends like a
// listed one, no name, and a stream that isn't TLS pass, and the module
// retires from them.
func TestSNIBlocklistPasses(t *testing.T) {
	m := buildPassive(t, "sni-blocklist", `{"names": ["example.net"], "verdict": "drop"}`)
	for name, stream := range map[string][]byte{
		"unlisted":     helloFor(t, "example.org"),
		"only a tail":  helloFor(t, "notexample.net"),
		"no name":      helloFor(t, ""),
		"not tls":      []byte("GET / HTTP/1.1\r\nHost: example.net\r\n\r\n"),
		"server first": {22, 3, 3, 0, 4, 2, 0, 0, 0},
	} {
		eng := NewEngine([]Passive{m}, nil, nil)
		seq := handshake(eng)
		if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, stream)); a.Verdict != Accept {
			t.Errorf("%s: %+v", name, a)
		}
		f := eng.flows.flows[FlowKey{ProtoTCP, clientAddr, serverAddr, 40000, 443}]
		if f.done == nil || !f.done[0] {
			t.Errorf("%s: the module didn't retire from the flow", name)
		}
	}
	if d := m.Inspect(udpPacket(clientAddr, serverAddr, 1, 443, helloFor(t, "example.net")), &Flow{}); d != retired {
		t.Errorf("udp: %+v", d)
	}
}

// TestSNIBlocklistOutgrowsPrefix: a ClientHello whose records outgrow
// the stream's prefix can never be read whole: once the prefix is full the
// module retires from the flow, its packets having passed.
func TestSNIBlocklistOutgrowsPrefix(t *testing.T) {
	m := buildPassive(t, "sni-blocklist", `{"names": ["example.net"]}`)
	// A message within the prefix, framed in 10-byte records: half again
	// as long on the wire.
	const msgLen = retainBytes - 1000
	msg := append([]byte{tlsClientHello, msgLen >> 16, msgLen >> 8 & 0xff, msgLen & 0xff}, make([]byte, msgLen)...)
	stream := splitRecords(append([]byte{tlsHandshake, 3, 1, 0, 0}, msg...), 10)
	eng := NewEngine([]Passive{m}, nil, nil)
	seq := handshake(eng)
	const segment = 1400
	for off := 0; off < retainBytes+segment; off += segment {
		end := min(off+segment, len(stream))
		if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq+uint32(off), 5001, Ack, stream[off:end])); a.Verdict != Accept {
			t.Fatalf("segment at %d: %+v", off, a)
		}
	}
	f := eng.flows.flows[FlowKey{ProtoTCP, clientAddr, serverAddr, 40000, 443}]
	if f.done == nil || !f.done[0] {
		t.Error("the module didn't retire from a flow whose ClientHello outgrew the prefix")
	}
}

// TestSNIBlocklistMidstream: a stream joined after its SYN isn't read
// from its first byte, so it isn't judged.
func TestSNIBlocklistMidstream(t *testing.T) {
	m := buildPassive(t, "sni-blocklist", `{"names": ["example.net"]}`)
	eng := NewEngine([]Passive{m}, nil, nil)
	if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1001, 5001, Ack|Psh, helloFor(t, "example.net"))); a.Verdict != Accept {
		t.Errorf("midstream: %+v", a)
	}
}

func TestSNIBlocklistSettings(t *testing.T) {
	for settings, wantErr := range map[string]string{
		`{}`:                                   "no names",
		`{"names": ["."]}`:                     `name ".": want a domain name`,
		`{"names": ["A..B."]}`:                 `name "A..B.": want a domain name`,
		`{"names": [".example.net"]}`:          `name ".example.net": want a domain name`,
		`{"names": ["blocked.example.net.."]}`: `name "blocked.example.net..": want a domain name`,
		`{"names": ["a"], "verdict": "x"}`:     "verdict",
	} {
		if _, err := newSNIBlocklist([]byte(settings)); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: err %v, want %q", settings, err, wantErr)
		}
	}
}
