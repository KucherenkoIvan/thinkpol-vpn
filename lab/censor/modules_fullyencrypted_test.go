package censor

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
)

// randomBytes is what a Shadowsocks-like client sends first: bytes no one
// can tell from random.
func randomBytes(seed uint64, n int) []byte {
	r := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// filler is n bytes of 4 set bits each, none printable: random-looking to
// every exemption, so a test adds exactly the one it checks.
func filler(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = []byte{0x0f, 0xf0}[i%2]
	}
	return b
}

// TestLooksFullyEncryptedExemptions checks each of Wu et al.'s exemptions
// on its own: every exempt case passes by that exemption alone, and the
// filler it is built on is flagged.
func TestLooksFullyEncryptedExemptions(t *testing.T) {
	// Printable bytes with 4 set bits each, so they don't move the average.
	const printable4 = "cefijl"
	run := func(n int) []byte { return bytes.Repeat([]byte(printable4), n/len(printable4)+1)[:n] }
	interleaved := bytes.Repeat([]byte{0xf0, 'c', 'e'}, 20)
	for _, c := range []struct {
		name   string
		b      []byte
		exempt bool
	}{
		{"filler", filler(60), false},
		{"random bytes", randomBytes(1, 600), false},
		{"3 set bits per byte", bytes.Repeat([]byte{0x07, 0x83, 0xc1}, 20), true},
		{"5 set bits per byte", bytes.Repeat([]byte{0x1f, 0xf8}, 30), true},
		{"3.4 set bits per byte", bytes.Repeat([]byte{0x0f, 0x0f, 0x0f, 0x07, 0x03}, 12), true},
		{"3.5 set bits per byte", bytes.Repeat([]byte{0x0f, 0x07}, 30), false},
		{"4.6 set bits per byte", bytes.Repeat([]byte{0x1f, 0x1f, 0x1f, 0xf0, 0xf0}, 12), true},
		{"4.5 set bits per byte", bytes.Repeat([]byte{0x1f, 0xf0}, 30), false},
		{"six printable first", append(run(6), filler(40)...), true},
		{"five printable first", append(run(5), filler(40)...), false},
		{"more than half printable", interleaved, true},
		{"half printable", bytes.Repeat([]byte{0xf0, 'c'}, 20), false},
		{"21 printable in a row", append(filler(60), run(21)...), true},
		{"20 printable in a row", append(filler(60), run(20)...), false},
		{"TLS handshake record", append([]byte{0x16, 0x03, 0x01}, filler(60)...), true},
		{"TLS application data", append([]byte{0x17, 0x03, 0x03}, filler(60)...), true},
		{"TLS minor version 10", append([]byte{0x16, 0x03, 0x0a}, filler(60)...), false},
		{"HTTP GET", append([]byte("GET "), filler(60)...), true},
		{"HTTP POST", append([]byte("POST "), filler(60)...), true},
		{"HTTP HEAD", append([]byte("HEAD "), filler(60)...), true},
		{"HTTP PUT", append([]byte("PUT "), filler(60)...), true},
		{"no method", append([]byte("GOT "), filler(60)...), false},
	} {
		why := looksFullyEncrypted(c.b)
		if (why == "") != c.exempt {
			t.Errorf("%s: flagged %q, want exempt %v", c.name, why, c.exempt)
		}
	}
}

// TestFullyEncryptedFlagsRandomNotHTTPS is the ticket's first check on the
// engine: a Shadowsocks-like random stream is dropped from its first data,
// over TCP and over UDP; HTTPS (a real ClientHello) and HTTP pass.
func TestFullyEncryptedFlagsRandomNotHTTPS(t *testing.T) {
	m, err := newFullyEncrypted(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		first []byte
		want  Verdict
	}{
		{"random", randomBytes(2, 300), Drop},
		{"TLS ClientHello", helloFor(t, "example.net"), Accept},
		{"HTTP", []byte("GET / HTTP/1.1\r\nHost: example.net\r\n\r\n"), Accept},
	} {
		eng := NewEngine([]Passive{m}, nil, nil)
		seq := handshake(eng)
		if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, c.first)); a.Verdict != c.want {
			t.Errorf("tcp %s: %+v, want %s", c.name, a, c.want)
		}
		later := tcpPacket(clientAddr, serverAddr, 40000, 443, seq+uint32(len(c.first)), 5001, Ack|Psh, []byte("GET / HTTP/1.1\r\n\r\n"))
		if a := eng.Handle(later); a.Verdict != c.want {
			t.Errorf("tcp %s: the next packet %+v, want the pinned %s", c.name, a, c.want)
		}

		eng = NewEngine([]Passive{m}, nil, nil)
		if a := eng.Handle(udpPacket(clientAddr, serverAddr, 5000, 443, c.first)); a.Verdict != c.want {
			t.Errorf("udp %s: %+v, want %s", c.name, a, c.want)
		}
	}
}

// TestFullyEncryptedJudgesTheClientOnly: a server's random first answer is
// not judged, a midstream connection isn't either, and only a UDP flow's
// first direction is.
func TestFullyEncryptedJudgesTheClientOnly(t *testing.T) {
	m, _ := newFullyEncrypted(nil)
	client, server := clientAddr, serverAddr
	random := randomBytes(3, 200)

	eng := NewEngine([]Passive{m}, nil, nil)
	seq := handshake(eng)
	get := []byte("GET / HTTP/1.1\r\n\r\n")
	if a := eng.Handle(tcpPacket(client, server, 40000, 443, seq, 5001, Ack|Psh, get)); a.Verdict != Accept {
		t.Errorf("the client's HTTP: %+v", a)
	}
	if a := eng.Handle(tcpPacket(server, client, 443, 40000, 5001, seq+uint32(len(get)), Ack|Psh, random)); a.Verdict != Accept {
		t.Errorf("the server's random answer: %+v", a)
	}

	eng = NewEngine([]Passive{m}, nil, nil)
	if a := eng.Handle(tcpPacket(client, server, 40001, 443, 7000, 9000, Ack|Psh, random)); a.Verdict != Accept {
		t.Errorf("midstream: %+v", a)
	}

	eng = NewEngine([]Passive{m}, nil, nil)
	if a := eng.Handle(udpPacket(client, server, 5000, 53, []byte("not random at all, a printable query"))); a.Verdict != Accept {
		t.Errorf("udp client's printable datagram: %+v", a)
	}
	if a := eng.Handle(udpPacket(server, client, 53, 5000, random)); a.Verdict != Accept {
		t.Errorf("udp server's random reply: %+v", a)
	}
	if a := eng.Handle(udpPacket(client, server, 5000, 53, random)); a.Verdict != Accept {
		t.Errorf("udp client's second datagram, after an exempt first: %+v", a)
	}
}

// TestFullyEncryptedTagOnly tags what it would block and lets it through,
// for the prober; the verdict and its tag reach the verdict log.
func TestFullyEncryptedTagOnly(t *testing.T) {
	var log bytes.Buffer
	m, err := newFullyEncrypted([]byte(`{"tagOnly": true}`))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine([]Passive{m}, nil, &log)
	p := udpPacket(clientAddr, serverAddr, 5000, 443, randomBytes(4, 100))
	if a := eng.Handle(p); a.Verdict != Accept {
		t.Errorf("tag only: %+v", a)
	}
	eng.Shutdown()
	if !strings.Contains(log.String(), `"event":"tag","flow":"udp 192.0.2.1:5000->203.0.113.9:443"`) ||
		!strings.Contains(log.String(), "fully encrypted: ") {
		t.Errorf("no tag in the verdict log:\n%s", log.String())
	}

	if _, err := newFullyEncrypted([]byte(`{"verdict": "poison"}`)); err == nil {
		t.Error("a bad verdict is accepted")
	}
}
