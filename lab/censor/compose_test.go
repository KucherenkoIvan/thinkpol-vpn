package censor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var (
	clientAddr = netip.MustParseAddr("192.0.2.1")
	serverAddr = netip.MustParseAddr("203.0.113.9")
)

// handshake opens a TCP connection through the engine, client to server
// port 443, and returns the client's next sequence number.
func handshake(eng *Engine) uint32 {
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1000, 0, Syn, nil))
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5000, 1001, Syn|Ack, nil))
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1001, 5001, Ack, nil))
	return 1001
}

// prefixWatcher records the stream prefix it is shown with each packet.
type prefixWatcher struct {
	prefixes [][]byte
	reverse  []*Flow
}

func (m *prefixWatcher) Name() string { return "watcher" }

func (m *prefixWatcher) Inspect(p *Packet, f *Flow) Decision {
	m.prefixes = append(m.prefixes, bytes.Clone(f.Stream.Prefix()))
	m.reverse = append(m.reverse, f.Reverse())
	return Decision{Verdict: Accept}
}

// TestEngineTwoSegmentClientHello: a ClientHello split over two segments,
// its server name in the second, is one prefix on the flow when a passive
// module sees the second segment, in order or not.
func TestEngineTwoSegmentClientHello(t *testing.T) {
	ch := clientHello(t)
	sni := bytes.Index(ch, []byte("example.net"))
	if sni < 100 {
		t.Fatalf("the server name is at %d: the split must put it in the second segment", sni)
	}
	for _, reversed := range []bool{false, true} {
		w := &prefixWatcher{}
		eng := NewEngine([]Passive{w}, nil, nil)
		seq := handshake(eng)
		first := tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack, ch[:100])
		second := tcpPacket(clientAddr, serverAddr, 40000, 443, seq+100, 5001, Ack|Psh, ch[100:])
		if reversed {
			first, second = second, first
		}
		eng.Handle(first)
		eng.Handle(second)
		if got := w.prefixes[len(w.prefixes)-1]; !bytes.Equal(got, ch) {
			t.Errorf("reversed %v: the module saw a %d-byte prefix, want the %d-byte ClientHello", reversed, len(got), len(ch))
		}
		if got := w.prefixes[len(w.prefixes)-2]; bytes.Contains(got, []byte("example.net")) {
			t.Errorf("reversed %v: the server name showed before its segment arrived", reversed)
		}
	}
}

// TestEngineLinksReverseFlows: each direction of a connection reaches the
// other, so a module seeing the server's hello finds the client's.
func TestEngineLinksReverseFlows(t *testing.T) {
	ch := clientHello(t)
	w := &prefixWatcher{}
	eng := NewEngine([]Passive{w}, nil, nil)
	if eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1000, 0, Syn, nil)); w.reverse[0] != nil {
		t.Fatal("a SYN has a reverse flow")
	}
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5000, 1001, Syn|Ack, nil))
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1001, 5001, Ack|Psh, ch))
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5001, 1001+uint32(len(ch)), Ack|Psh, []byte("\x16\x03\x03server hello")))

	server := w.reverse[1] // the SYN-ACK's reverse: the client's flow
	if server == nil || server.Key.Src != clientAddr || !bytes.Equal(server.Stream.Prefix(), ch) {
		t.Fatalf("the server's flow links to %+v, want the client's with its ClientHello", server)
	}
	client := w.reverse[2]
	if client == nil || client.Reverse() != server || string(client.Stream.Prefix()) != "\x16\x03\x03server hello" {
		t.Errorf("the client's flow links to %+v, want the server's with its hello", client)
	}
}

// acceptPinner pins Accept on the first packet it sees.
type acceptPinner struct{ saw int }

func (m *acceptPinner) Name() string { return "allow" }

func (m *acceptPinner) Inspect(*Packet, *Flow) Decision {
	m.saw++
	return Decision{Verdict: Accept, Flow: true}
}

// dropAfter drops a flow's packets from the n-th on, without pinning.
type dropAfter struct {
	n, saw int
}

func (m *dropAfter) Name() string { return "late-block" }

func (m *dropAfter) Inspect(*Packet, *Flow) Decision {
	m.saw++
	if m.saw >= m.n {
		return Decision{Verdict: Drop, Reason: "late"}
	}
	return Decision{Verdict: Accept}
}

// TestEngineCompositionAcceptIsNotTerminal is the chosen rule (review S9):
// only blocking verdicts are terminal. A module's pinned Accept retires
// that module from the flow, and a later module, or an active module's
// flag, still blocks it.
func TestEngineCompositionAcceptIsNotTerminal(t *testing.T) {
	p := udpPacket(clientAddr, serverAddr, 1, 2, []byte("x"))

	allow, late := &acceptPinner{}, &dropAfter{n: 3}
	eng := NewEngine([]Passive{allow, late}, nil, nil)
	var got []Verdict
	for i := 0; i < 3; i++ {
		got = append(got, eng.Handle(p).Verdict)
	}
	if got[0] != Accept || got[1] != Accept || got[2] != Drop {
		t.Errorf("verdicts %v: a pinned Accept stopped a later module's drop", got)
	}
	if allow.saw != 1 || late.saw != 3 {
		t.Errorf("the pinning module saw %d packets (want 1), the later one %d (want 3)", allow.saw, late.saw)
	}

	// A flag over a pinned Accept.
	eng = NewEngine([]Passive{&acceptPinner{}}, nil, nil)
	eng.Handle(p)
	eng.flagFunc("prober")(FlowKey{ProtoUDP, clientAddr, serverAddr, 1, 2}, Drop, "probed")
	if a := eng.Handle(p); a.Verdict != Drop || a.Module != "prober" {
		t.Errorf("a flag after a pinned Accept: %+v", a)
	}
}

// TestEngineCompositionSeverity: a flow's verdict changes only to a more
// severe one, and an Accept flag changes nothing.
func TestEngineCompositionSeverity(t *testing.T) {
	key := FlowKey{ProtoUDP, clientAddr, serverAddr, 1, 2}
	p := udpPacket(clientAddr, serverAddr, 1, 2, nil)
	for _, c := range []struct {
		pinned   Decision
		flag     Verdict
		want     Verdict
		wantFrom string
	}{
		{Decision{Verdict: Throttle, Flow: true}, Drop, Drop, "prober"},
		{Decision{Verdict: Drop, Flow: true}, Throttle, Drop, "pin"},
		{Decision{Verdict: Drop, Flow: true}, Accept, Drop, "pin"},
		{Decision{Verdict: Accept, Flow: true}, Accept, Accept, ""},
	} {
		eng := NewEngine([]Passive{&fixed{c.pinned}}, nil, nil)
		eng.Handle(p)
		eng.flagFunc("prober")(key, c.flag, "probed")
		a := eng.Handle(p)
		got := a.Verdict
		if a.Throttled {
			got = Throttle
		}
		if got != c.want || a.Module != c.wantFrom {
			t.Errorf("pinned %v, flagged %v: %+v, want %v from %q", c.pinned.Verdict, c.flag, a, c.want, c.wantFrom)
		}
	}
}

// TestEngineCompositionThrottleIsNotTerminal: a Throttle, pinned or not,
// never stops a later module from dropping or resetting the flow; in
// either config order the drop wins once it comes, and the throttle
// polices the packets before it.
func TestEngineCompositionThrottleIsNotTerminal(t *testing.T) {
	p := udpPacket(clientAddr, serverAddr, 1, 2, []byte("x"))
	for _, pinned := range []bool{false, true} {
		for _, throttleFirst := range []bool{true, false} {
			throttle := &fixed{Decision{Verdict: Throttle, Flow: pinned}}
			late := &dropAfter{n: 2}
			mods := []Passive{throttle, late}
			if !throttleFirst {
				mods = []Passive{late, throttle}
			}
			eng := NewEngine(mods, nil, nil)
			if a := eng.Handle(p); a.Verdict != Accept || !a.Throttled {
				t.Errorf("pinned %v, throttle first %v: the first packet %+v, want throttled and within the rate", pinned, throttleFirst, a)
			}
			for i := 2; i <= 3; i++ {
				if a := eng.Handle(p); a.Verdict != Drop || a.Module != "late-block" {
					t.Errorf("pinned %v, throttle first %v: packet %d %+v, want late-block's drop", pinned, throttleFirst, i, a)
				}
			}
		}
	}
}

// TestEngineFlagsMergeBySeverity: of two flags waiting for a flow's next
// packet, the more severe one is applied, whatever their order.
func TestEngineFlagsMergeBySeverity(t *testing.T) {
	key := FlowKey{ProtoUDP, clientAddr, serverAddr, 1, 2}
	p := udpPacket(clientAddr, serverAddr, 1, 2, nil)
	eng := NewEngine(nil, nil, nil)
	eng.Handle(p)
	eng.flagFunc("a")(key, Drop, "first")
	eng.flagFunc("b")(key, Throttle, "second")
	if a := eng.Handle(p); a.Verdict != Drop || a.Module != "a" {
		t.Errorf("drop then throttle: %+v, want a's drop", a)
	}
}

// fixed decides every packet the same way.
type fixed struct{ d Decision }

func (m *fixed) Name() string                    { return "pin" }
func (m *fixed) Inspect(*Packet, *Flow) Decision { return m.d }

// tagger tags each flow on its second packet, and again on later ones.
type tagger struct{}

func (tagger) Name() string { return "suspicious" }

func (tagger) Inspect(_ *Packet, f *Flow) Decision {
	if f.Packets >= 2 {
		return Decision{Verdict: Accept, Tag: "looks random"}
	}
	return Decision{Verdict: Accept}
}

// TestEngineTagReachesActive: a passive module's tag hands the flow, with
// its retained payload, to the active modules, once.
func TestEngineTagReachesActive(t *testing.T) {
	prober := &proberModule{ch: make(chan FlowSnapshot, 8)}
	eng := NewEngine([]Passive{tagger{}}, []Active{prober}, nil)
	defer eng.Shutdown()
	for _, payload := range []string{"first", "second", "third"} {
		eng.Handle(udpPacket(clientAddr, serverAddr, 1, 2, []byte(payload)))
	}
	var snaps []FlowSnapshot
	deadline := time.After(5 * time.Second)
	for len(snaps) < 2 {
		select {
		case s := <-prober.ch:
			snaps = append(snaps, s)
		case <-deadline:
			t.Fatalf("the active module got %d snapshots, want the new flow and its tag", len(snaps))
		}
	}
	if snaps[0].Tagger != "" || snaps[1].Tagger != "suspicious" || snaps[1].Tag != "looks random" {
		t.Errorf("snapshots %+v", snaps)
	}
	if string(snaps[1].Payload) != "first" || snaps[1].Packets != 2 {
		t.Errorf("the tagged flow's payload %q at packet %d, want the first datagram at 2", snaps[1].Payload, snaps[1].Packets)
	}
	select {
	case s := <-prober.ch:
		t.Errorf("a second tag of the flow reached the module: %+v", s)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestReplayIsPassiveAndActive builds replay, one module that is both:
// its passive half tags the flow once the two-segment ClientHello is
// whole, and its active half sends that ClientHello, retained, to the
// flow's destination.
func TestReplayIsPassiveAndActive(t *testing.T) {
	passives, actives, err := Build(Config{Modules: []ModuleConfig{
		{Name: "replay", Settings: json.RawMessage(`{"destinations": ["203.0.113.0/24"]}`)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(passives) != 1 || len(actives) != 1 || passives[0] != actives[0].(Passive) {
		t.Fatalf("replay built as %d passives and %d actives, want one value in both", len(passives), len(actives))
	}
	type dialed struct {
		addr string
		got  []byte
	}
	got := make(chan dialed, 1)
	passives[0].(*replay).dial = func(_ context.Context, network, addr string) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			b, _ := io.ReadAll(s)
			got <- dialed{addr, b}
		}()
		return c, nil
	}
	eng := NewEngine(passives, actives, nil)
	defer eng.Shutdown()

	ch := clientHello(t)
	seq := handshake(eng)
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack, ch[:100]))
	select {
	case d := <-got:
		t.Fatalf("replayed %d bytes before the ClientHello was whole", len(d.got))
	case <-time.After(100 * time.Millisecond):
	}
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq+100, 5001, Ack|Psh, ch[100:]))
	select {
	case d := <-got:
		if d.addr != "203.0.113.9:443" || !bytes.Equal(d.got, ch) {
			t.Errorf("replayed %d bytes to %s, want the %d-byte ClientHello to 203.0.113.9:443", len(d.got), d.addr, len(ch))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing replayed")
	}
}

// TestEngineLogBoundedPerFlow: a long flow logs one entry per verdict and
// module it gets, and a summary at shutdown, however many packets it has
// and however often its verdict alternates.
func TestEngineLogBoundedPerFlow(t *testing.T) {
	var buf bytes.Buffer
	eng := NewEngine([]Passive{&dropAfter{n: 501}}, nil, &buf)
	p := udpPacket(clientAddr, serverAddr, 1, 2, []byte("x"))
	for i := 0; i < 1000; i++ {
		eng.Handle(p)
	}
	// Data dropped, empty packets accepted, alternating.
	m, err := newBlockIP([]byte(`{"destinations": ["203.0.113.9"], "data": true}`))
	if err != nil {
		t.Fatal(err)
	}
	var altBuf bytes.Buffer
	alternating := NewEngine([]Passive{m}, nil, &altBuf)
	for i := 0; i < 1000; i++ {
		alternating.Handle(tcpPacket(clientAddr, serverAddr, 3, 4, uint32(i), 1, Ack, []byte("x")[:i%2]))
	}
	alternating.Shutdown()
	if n := strings.Count(altBuf.String(), "\n"); n != 3 {
		t.Errorf("a flow alternating accept and drop logged %d lines, want 3:\n%s", n, altBuf.String())
	}
	eng.Shutdown()

	var entries []LogEntry
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 3 {
		t.Fatalf("%d entries for one flow of 1000 packets, want 3:\n%s", len(entries), buf.String())
	}
	if e := entries[0]; e.Event != EventDecision || e.Verdict != Accept || e.Packets != 1 {
		t.Errorf("first: %+v", e)
	}
	if e := entries[1]; e.Event != EventDecision || e.Verdict != Drop || e.Module != "late-block" || e.Packets != 501 {
		t.Errorf("the change: %+v", e)
	}
	if e := entries[2]; e.Event != EventSummary || e.Packets != 1000 || e.Applied["accept"] != 500 || e.Applied["drop"] != 500 {
		t.Errorf("summary: %+v", e)
	}
}

// TestEngineIgnoresWhatReceiverDiscards: a decoy with a bad checksum at
// the ClientHello's sequence number, which the server discards, stays out
// of the stream, so the module reads the real ClientHello sent after it;
// the verdict log says so once, and the summary counts both decoys.
func TestEngineIgnoresWhatReceiverDiscards(t *testing.T) {
	ch := clientHello(t)
	var buf bytes.Buffer
	w := &prefixWatcher{}
	eng := NewEngine([]Passive{w}, nil, &buf)
	seq := handshake(eng)
	for i := 0; i < 2; i++ {
		decoy := tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, bytes.Repeat([]byte("d"), len(ch)))
		decoy.BadChecksum = true
		eng.Handle(decoy)
	}
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, ch))
	if got := w.prefixes[len(w.prefixes)-1]; !bytes.Equal(got, ch) {
		t.Errorf("the module read %d bytes, want the real %d-byte ClientHello", len(got), len(ch))
	}
	eng.Shutdown()
	var ignores int
	var summary LogEntry
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		switch {
		case e.Event == EventIgnore && e.Reason == ignoreBadChecksum:
			ignores++
		case e.Event == EventSummary && e.Flow == "tcp 192.0.2.1:40000->203.0.113.9:443":
			summary = e
		}
	}
	if ignores != 1 || summary.Ignored[ignoreBadChecksum] != 2 {
		t.Errorf("%d ignore entries (want 1), summary ignored %v (want 2 bad checksums):\n%s", ignores, summary.Ignored, buf.String())
	}
}

// nameJudge pins Drop on a flow whose retained payload names "blocked"
// and Accept on one naming "allowed", as an SNI module would.
type nameJudge struct{}

func (nameJudge) Name() string { return "names" }

func (nameJudge) Inspect(_ *Packet, f *Flow) Decision {
	switch {
	case bytes.Contains(f.Payload(), []byte("blocked")):
		return Decision{Verdict: Drop, Flow: true}
	case bytes.Contains(f.Payload(), []byte("allowed")):
		return Decision{Verdict: Accept, Flow: true}
	}
	return Decision{Verdict: Accept}
}

// TestEngineNewConnectionStartsOver: a new TCP connection on an old one's
// addresses and ports, once the server's SYN-ACK accepts it, is read and
// judged from its own first byte, not by the old one's retired module and
// stream; a SYN the server never accepts (or a SYN-ACK the client
// discards) changes nothing, so it can't shake off a pinned drop; a UDP
// flow starts over after udpIdle without a datagram the receiver accepts.
func TestEngineNewConnectionStartsOver(t *testing.T) {
	data := func(seq uint32, s string) *Packet {
		return tcpPacket(clientAddr, serverAddr, 40000, 443, seq, 5001, Ack|Psh, []byte(s))
	}
	eng := NewEngine([]Passive{nameJudge{}}, nil, nil)
	seq := handshake(eng)
	if a := eng.Handle(data(seq, "allowed")); a.Verdict != Accept {
		t.Fatalf("the first connection: %+v", a)
	}
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, seq+7, 5001, Fin|Ack, nil))
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 900000, 0, Syn, nil))
	eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 70000, 900001, Syn|Ack, nil))
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 900001, 70001, Ack, nil))
	if a := eng.Handle(data(900001, "blocked")); a.Verdict != Drop || a.Module != "names" {
		t.Errorf("a new connection on the same ports: %+v, want its own ClientHello dropped", a)
	}
	client := eng.flows.flows[FlowKey{ProtoTCP, clientAddr, serverAddr, 40000, 443}]
	server := eng.flows.flows[FlowKey{ProtoTCP, serverAddr, clientAddr, 443, 40000}]
	// The SYN counts in the old client flow, which it reached first.
	if client.Reverse() != server || server.Reverse() != client || client.Packets != 2 || server.Packets != 1 {
		t.Errorf("new connection's flows: client %d packets, server %d, linked %v", client.Packets, server.Packets, client.Reverse() == server && server.Reverse() == client)
	}

	// A SYN alone, which the server would ignore, lifts no pinned drop;
	// nor does a SYN-ACK with a bad checksum, which the client discards.
	eng = NewEngine([]Passive{nameJudge{}}, nil, nil)
	seq = handshake(eng)
	eng.Handle(data(seq, "blocked"))
	eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 900000, 0, Syn, nil))
	fake := tcpPacket(serverAddr, clientAddr, 443, 40000, 70000, 900001, Syn|Ack, nil)
	fake.BadChecksum = true
	eng.Handle(fake)
	if a := eng.Handle(data(seq, "blocked")); a.Verdict != Drop {
		t.Errorf("after a SYN nobody accepted: %+v, want the pinned drop", a)
	}

	// UDP: a flow silent past udpIdle starts over.
	clock := time.Unix(1000, 0)
	eng = NewEngine([]Passive{nameJudge{}}, nil, nil)
	eng.now = func() time.Time { return clock }
	eng.Handle(udpPacket(clientAddr, serverAddr, 1, 2, []byte("allowed")))
	// Datagrams the receiver discards keep nothing alive.
	clock = clock.Add(udpIdle - time.Second)
	junk := udpPacket(clientAddr, serverAddr, 1, 2, []byte("junk"))
	junk.BadChecksum = true
	eng.Handle(junk)
	clock = clock.Add(2 * time.Second)
	if a := eng.Handle(udpPacket(clientAddr, serverAddr, 1, 2, []byte("blocked"))); a.Verdict != Drop {
		t.Errorf("a UDP flow after %v idle: %+v, want its new first datagram judged", udpIdle, a)
	}
}
