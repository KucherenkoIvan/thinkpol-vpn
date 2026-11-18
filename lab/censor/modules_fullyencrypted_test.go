package censor

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
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

// TestJudgeFirstDataExemptions checks each of Wu et al.'s exemptions on
// its own: every exempt case passes by that exemption alone, which its
// reason names, and the filler it is built on is flagged.
func TestJudgeFirstDataExemptions(t *testing.T) {
	// Printable bytes with 4 set bits each, so they don't move the average.
	const printable4 = "cefijl"
	run := func(n int) []byte { return bytes.Repeat([]byte(printable4), n/len(printable4)+1)[:n] }
	interleaved := bytes.Repeat([]byte{0xf0, 'c', 'e'}, 20)
	for _, c := range []struct {
		name string
		b    []byte
		// exemption is what the exemption's reason says, "" when flagged.
		exemption string
	}{
		{"filler", filler(60), ""},
		{"random bytes", randomBytes(1, 600), ""},
		{"3 set bits per byte", bytes.Repeat([]byte{0x07, 0x83, 0xc1}, 20), "3.00 set bits per byte"},
		{"5 set bits per byte", bytes.Repeat([]byte{0x1f, 0xf8}, 30), "5.00 set bits per byte"},
		{"3.4 set bits per byte", bytes.Repeat([]byte{0x0f, 0x0f, 0x0f, 0x07, 0x03}, 12), "3.40 set bits per byte"},
		{"3.5 set bits per byte", bytes.Repeat([]byte{0x0f, 0x07}, 30), ""},
		{"4.6 set bits per byte", bytes.Repeat([]byte{0x1f, 0x1f, 0x1f, 0xf0, 0xf0}, 12), "4.60 set bits per byte"},
		{"4.5 set bits per byte", bytes.Repeat([]byte{0x1f, 0xf0}, 30), ""},
		{"six printable first", append(run(6), filler(40)...), "first six bytes printable"},
		{"five printable first", append(run(5), filler(40)...), ""},
		{"more than half printable", interleaved, "more than half printable, 40 of 60"},
		{"half printable", bytes.Repeat([]byte{0xf0, 'c'}, 20), ""},
		{"21 printable in a row", append(filler(60), run(21)...), "a printable run of 21"},
		{"20 printable in a row", append(filler(60), run(20)...), ""},
		{"TLS handshake record", append([]byte{0x16, 0x03, 0x01}, filler(60)...), "a TLS or HTTP start"},
		{"TLS application data", append([]byte{0x17, 0x03, 0x03}, filler(60)...), "a TLS or HTTP start"},
		{"TLS minor version 10", append([]byte{0x16, 0x03, 0x0a}, filler(60)...), ""},
		{"HTTP GET", append([]byte("GET "), filler(60)...), "a TLS or HTTP start"},
		{"HTTP POST", append([]byte("POST "), filler(60)...), "a TLS or HTTP start"},
		{"HTTP HEAD", append([]byte("HEAD "), filler(60)...), "a TLS or HTTP start"},
		{"HTTP PUT", append([]byte("PUT "), filler(60)...), "a TLS or HTTP start"},
		{"no method", append([]byte("GOT "), filler(60)...), ""},
	} {
		why, exempt := judgeFirstData(c.b)
		if exempt != (c.exemption != "") || !strings.Contains(why, c.exemption) {
			t.Errorf("%s: %q, exempt %v, want exempt by %q", c.name, why, exempt, c.exemption)
		}
	}
}

// TestFullyEncryptedFlagsRandomNotHTTPS is the ticket's first check on the
// engine: a Shadowsocks-like random stream is dropped from its first data,
// over TCP and over UDP; HTTPS (a real ClientHello) and HTTP pass.
func TestFullyEncryptedFlagsRandomNotHTTPS(t *testing.T) {
	newModule := func() Passive {
		m, err := newFullyEncrypted(nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
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
		eng := NewEngine([]Passive{newModule()}, nil, nil)
		seq := handshake(eng)
		if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, c.first)); a.Verdict != c.want {
			t.Errorf("tcp %s: %+v, want %s", c.name, a, c.want)
		}
		later := tcpPacket(clientAddr, serverAddr, 40000, 443, seq+uint32(len(c.first)), 5001, Ack|Psh, []byte("GET / HTTP/1.1\r\n\r\n"))
		if a := eng.Handle(later); a.Verdict != c.want {
			t.Errorf("tcp %s: the next packet %+v, want the pinned %s", c.name, a, c.want)
		}

		eng = NewEngine([]Passive{newModule()}, nil, nil)
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

// TestFullyEncryptedWireGuardInitiationByChance measures why the matrix's
// WireGuard cell varies: an initiation is 128 random bytes behind a type
// and three zero bytes, with mac2's 16 zero bytes at its end (no cookie),
// about 3.47 set bits per byte, so the first exemption (at most 3.4)
// passes about one in four. thinkpol's udp sends no zero runs: a datagram
// that size, all random, is exempt almost never but by its first six
// bytes (its connection id, fixed for the link's hour), while an 84-byte
// one (a redial's first in the lab) is exempt about one in 115 on average
// over connection ids, more than half printable about one in 175 of them,
// each new flow's first datagram a fresh draw: TP-236's partial cell,
// which residual censorship leaves one draw per 3-tuple and residual
// window.
func TestFullyEncryptedWireGuardInitiationByChance(t *testing.T) {
	const n = 2000
	exempt, udpExempt, shortExempt := 0, 0, 0
	for seed := uint64(0); seed < 10*n; seed++ {
		if _, ok := judgeFirstData(randomBytes(seed+2*n, 84)); ok {
			shortExempt++
		}
	}
	if shortExempt < n/100 || shortExempt > n/5 {
		t.Errorf("%d of %d 84-byte random datagrams exempt, want about one in 115", shortExempt, 10*n)
	}
	for seed := uint64(0); seed < n; seed++ {
		init := randomBytes(seed, wgInitiation)
		copy(init, []byte{wgTypeInitiation, 0, 0, 0})
		clear(init[wgInitiation-16:])
		if _, ok := judgeFirstData(init); ok {
			exempt++
		}
		if _, ok := judgeFirstData(randomBytes(seed+n, wgInitiation)); ok {
			udpExempt++
		}
	}
	if exempt < n/8 || exempt > n/2 {
		t.Errorf("%d of %d WireGuard initiations exempt, want about a quarter", exempt, n)
	}
	if udpExempt > n/100 {
		t.Errorf("%d of %d random datagrams exempt, want almost none", udpExempt, n)
	}
	t.Logf("exempt: %d of %d WireGuard initiations, %d of %d random datagrams, %d of %d 84-byte ones", exempt, n, udpExempt, n, shortExempt, 10*n)
}

// redialDatagram is shaped like thinkpol's udp datagram that crossed in
// TP-236: 84 bytes, a connection id then random-looking bytes, exempt
// only because more than half of it happens to be printable (4 set bits
// per byte, no printable start, no long printable run).
func redialDatagram() []byte {
	return append(filler(8), bytes.Repeat([]byte{0xf0, 'c', 'e'}, 26)[:76]...)
}

// residualRun is an engine with fully-encrypted set up by settings, on a
// clock the test moves.
type residualRun struct {
	t     *testing.T
	m     *fullyEncrypted
	eng   *Engine
	clock time.Time
}

func newResidualRun(t *testing.T, settings string) *residualRun {
	t.Helper()
	p, err := newFullyEncrypted([]byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	r := &residualRun{t: t, m: p.(*fullyEncrypted), clock: time.Unix(1000, 0)}
	r.eng = NewEngine([]Passive{p}, nil, nil)
	r.eng.now = func() time.Time { return r.clock }
	return r
}

func (r *residualRun) expect(what string, p *Packet, want Verdict) Action {
	r.t.Helper()
	a := r.eng.Handle(p)
	if a.Verdict != want {
		r.t.Errorf("%s: %+v, want %s", what, a, want)
	}
	return a
}

// TestFullyEncryptedResidualCensorship: once it blocks a UDP flow, every
// packet its client sends to the server's address and port is dropped for
// residualCensorship, whatever it looks like: a redial from a new port
// whose first datagram an exemption passes (TP-236's partial cell), a
// flow exempt before the block, and TCP to the same port (a UDP block
// covers both protocols). The server's packets, other clients, other
// server addresses and ports, and the client's other family are judged as
// before; the time runs from the block, not from the drops, and a block
// after it ran out starts another.
func TestFullyEncryptedResidualCensorship(t *testing.T) {
	blocked, exempt := randomBytes(5, 84), redialDatagram()
	if _, ok := judgeFirstData(blocked); ok {
		t.Fatal("the blocked datagram is exempt")
	}
	if _, ok := judgeFirstData(exempt); !ok {
		t.Fatal("the exempt datagram is flagged")
	}
	r := newResidualRun(t, "")
	start := r.clock
	other := netip.MustParseAddr("192.0.2.2")
	otherServer := netip.MustParseAddr("203.0.113.10")
	client6, server6 := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::9")

	r.expect("an exempt flow before the block", udpPacket(clientAddr, serverAddr, 4999, 4500, exempt), Accept)
	r.expect("the blocked flow", udpPacket(clientAddr, serverAddr, 5000, 4500, blocked), Drop)
	r.expect("a block on another port, never revisited", udpPacket(clientAddr, serverAddr, 5100, 4502, blocked), Drop)
	r.clock = r.clock.Add(time.Second)
	a := r.expect("the exempt flow after the block", udpPacket(clientAddr, serverAddr, 4999, 4500, exempt), Drop)
	if !strings.Contains(a.Reason, "residual censorship of udp 192.0.2.1->203.0.113.9:4500 from ") {
		t.Errorf("a residual drop's reason %q names no residual window", a.Reason)
	}
	r.expect("a redial an exemption passes", udpPacket(clientAddr, serverAddr, 5001, 4500, exempt), Drop)
	r.expect("the server's reply to it", udpPacket(serverAddr, clientAddr, 4500, 5001, blocked), Accept)
	r.expect("another client", udpPacket(other, serverAddr, 5001, 4500, exempt), Accept)
	r.expect("another server port", udpPacket(clientAddr, serverAddr, 5002, 4501, exempt), Accept)
	r.expect("the same client port to another server address", udpPacket(clientAddr, otherServer, 5001, 4500, exempt), Accept)
	r.expect("the same client over IPv6", udpPacket(client6, server6, 5001, 4500, exempt), Accept)
	r.expect("TCP to the same port", tcpPacket(clientAddr, serverAddr, 40000, 4500, 1000, 0, Syn, nil), Drop)

	r.clock = start.Add(residualCensorship - time.Millisecond)
	r.expect("a redial just before the time is up", udpPacket(clientAddr, serverAddr, 5003, 4500, exempt), Drop)
	r.clock = start.Add(residualCensorship)
	r.expect("a redial once the time is up", udpPacket(clientAddr, serverAddr, 5004, 4500, exempt), Accept)
	r.expect("the redial dropped before, judged on its first datagram", udpPacket(clientAddr, serverAddr, 5003, 4500, exempt), Accept)
	r.expect("a TCP connection once the time is up", tcpPacket(clientAddr, serverAddr, 40001, 4500, 1000, 0, Syn, nil), Accept)

	r.expect("a block after the time ran out", udpPacket(clientAddr, serverAddr, 5005, 4500, blocked), Drop)
	r.expect("a redial after it", udpPacket(clientAddr, serverAddr, 5006, 4500, exempt), Drop)
	r.expect("the flow exempt since before the first block", udpPacket(clientAddr, serverAddr, 4999, 4500, exempt), Drop)
	if len(r.m.residual) != 2 {
		t.Errorf("residual censorship holds %v, want the last block's two protocols alone, the expired ones removed", r.m.residual)
	}

	r = newResidualRun(t, "")
	r.expect("a blocked IPv6 flow", udpPacket(client6, server6, 5000, 4500, blocked), Drop)
	r.expect("an IPv6 redial", udpPacket(client6, server6, 5001, 4500, exempt), Drop)
	r.expect("the same client over IPv4", udpPacket(clientAddr, serverAddr, 5001, 4500, exempt), Accept)

	tagger := newResidualRun(t, `{"tagOnly": true}`)
	tagger.expect("a tagged flow", udpPacket(clientAddr, serverAddr, 5000, 4500, blocked), Accept)
	tagger.expect("a redial after a tag", udpPacket(clientAddr, serverAddr, 5001, 4500, exempt), Accept)
}

// TestFullyEncryptedResidualCensorshipTCP: a blocked TCP connection's
// 3-tuple drops a connection established and exempt before the block, and
// a new connection's SYN, but not UDP to the same port, which Wu et al.
// saw a TCP block leave alone.
func TestFullyEncryptedResidualCensorshipTCP(t *testing.T) {
	r := newResidualRun(t, "")
	seq := handshake(r.eng)
	get := []byte("GET / HTTP/1.1\r\n\r\n")
	r.expect("an exempt connection", tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, get), Accept)
	seq += uint32(len(get))

	r.expect("another connection's SYN", tcpPacket(clientAddr, serverAddr, 40001, 443, 7000, 0, Syn, nil), Accept)
	r.expect("its SYN-ACK", tcpPacket(serverAddr, clientAddr, 443, 40001, 9000, 7001, Syn|Ack, nil), Accept)
	r.expect("its ACK", tcpPacket(clientAddr, serverAddr, 40001, 443, 7001, 9001, Ack, nil), Accept)
	r.expect("its random first data", tcpPacket(clientAddr, serverAddr, 40001, 443, 7001, 9001, Ack|Psh, randomBytes(6, 200)), Drop)

	r.clock = r.clock.Add(time.Second)
	r.expect("the exempt connection's next data", tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, get), Drop)
	r.expect("the server's data on it", tcpPacket(serverAddr, clientAddr, 443, 40000, 5001, seq, Ack|Psh, randomBytes(7, 100)), Accept)
	r.expect("a new connection's SYN", tcpPacket(clientAddr, serverAddr, 40002, 443, 8000, 0, Syn, nil), Drop)
	r.expect("UDP to the same port", udpPacket(clientAddr, serverAddr, 40003, 443, redialDatagram()), Accept)
}

// TestFullyEncryptedResidualCensorshipDrops whatever the module's verdict:
// a throttle or a reset is the blocked connection's alone, and residual
// censorship neither throttles the server's replies to a redial nor
// resets one.
func TestFullyEncryptedResidualCensorshipDrops(t *testing.T) {
	r := newResidualRun(t, `{"verdict": "throttle", "rate": 100, "burst": 100}`)
	if a := r.eng.Handle(udpPacket(clientAddr, serverAddr, 5000, 4500, randomBytes(5, 84))); !a.Throttled {
		t.Errorf("the blocked flow: %+v, want throttled", a)
	}
	if a := r.expect("a throttling module's redial", udpPacket(clientAddr, serverAddr, 5001, 4500, redialDatagram()), Drop); a.Throttled {
		t.Errorf("a throttling module's redial is throttled: %+v", a)
	}
	for i := range 5 {
		if a := r.expect("the server's reply to the redial", udpPacket(serverAddr, clientAddr, 4500, 5001, randomBytes(8, 1000)), Accept); a.Throttled {
			t.Errorf("the server's reply %d to a redial is throttled: %+v", i, a)
			break
		}
	}

	r = newResidualRun(t, `{"verdict": "reset"}`)
	seq := handshake(r.eng)
	r.expect("the blocked connection", tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, randomBytes(6, 200)), Reset)
	r.expect("a resetting module's new SYN", tcpPacket(clientAddr, serverAddr, 40001, 443, 7000, 0, Syn, nil), Drop)
}

// TestFullyEncryptedExemptions: an exempt flow's accept names its
// exemption and who opened the flow in the verdict log, once per flow; a
// flow that starts over on the same addresses and ports is judged afresh,
// and the module keeps one exempt entry per flow key.
func TestFullyEncryptedExemptions(t *testing.T) {
	var log bytes.Buffer
	p, err := newFullyEncrypted(nil)
	if err != nil {
		t.Fatal(err)
	}
	m := p.(*fullyEncrypted)
	eng := NewEngine([]Passive{m}, nil, &log)
	clock := time.Unix(1000, 0)
	eng.now = func() time.Time { return clock }
	for range 3 {
		if a := eng.Handle(udpPacket(clientAddr, serverAddr, 5000, 4500, redialDatagram())); a.Verdict != Accept {
			t.Errorf("an exempt datagram: %+v", a)
		}
	}
	seq := handshake(eng)
	if a := eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, append([]byte("GET "), filler(60)...))); a.Verdict != Accept {
		t.Errorf("an exempt TCP connection: %+v", a)
	}
	clock = clock.Add(udpIdle + time.Second)
	if a := eng.Handle(udpPacket(clientAddr, serverAddr, 5000, 4500, randomBytes(5, 84))); a.Verdict != Drop {
		t.Errorf("a random datagram once the exempt flow started over: %+v", a)
	}
	if len(m.exempt) != 2 {
		t.Errorf("exempt flows %v, want one per flow key", m.exempt)
	}
	eng.Shutdown()

	reasons := map[string][]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(log.String()), "\n") {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Event == EventDecision && e.Verdict == Accept && e.Module == "fully-encrypted" {
			reasons[e.Flow] = append(reasons[e.Flow], e.Reason)
		}
	}
	want := map[string][]string{
		"udp 192.0.2.1:5000->203.0.113.9:4500": {"exempt: more than half printable, 50 of 84 bytes; opened by 192.0.2.1:5000 (the side seen first)"},
		"tcp 192.0.2.1:40000->203.0.113.9:443": {"exempt: a TLS or HTTP start, 64 bytes; opened by 192.0.2.1:40000 (its SYN)"},
	}
	if !reflect.DeepEqual(reasons, want) {
		t.Errorf("exempt accepts in the verdict log %q, want %q", reasons, want)
	}
}
