package censor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// wgMessage is one WireGuard message a udp-in-TLS-like transport carries,
// in a TLS application-data record of its own: at offset into the run,
// from the client or the server, size bytes before the transport's
// overhead.
type wgMessage struct {
	at       time.Duration
	toServer bool
	size     int
}

// wgTimeline is a WireGuard tunnel's messages over 260 s, with the
// rhythm: the first handshake, a burst of data, persistent keepalives
// every 25 s while idle, a rekey 121 s in and again 121 s later.
func wgTimeline(keepalives bool) []wgMessage {
	var msgs []wgMessage
	handshake := func(at time.Duration) {
		msgs = append(msgs,
			wgMessage{at, true, wgInitiation},
			wgMessage{at + 15*time.Millisecond, false, wgResponse})
	}
	burst := func(from, to time.Duration) {
		for at, i := from, 0; at < to; at, i = at+time.Second, i+1 {
			msgs = append(msgs,
				wgMessage{at, true, wgKeepalive + 16*(1+i%60)},
				wgMessage{at + 20*time.Millisecond, false, wgKeepalive + 16*(1+(i*7)%80)})
		}
	}
	idle := func(from, to time.Duration) {
		for at := from + 25*time.Second; keepalives && at < to; at += 25 * time.Second {
			msgs = append(msgs, wgMessage{at, true, wgKeepalive})
		}
	}
	handshake(0)
	burst(time.Second, 11*time.Second)
	idle(10*time.Second, 121*time.Second)
	handshake(121 * time.Second)
	burst(122*time.Second, 131*time.Second)
	idle(130*time.Second, 242*time.Second)
	handshake(242 * time.Second)
	burst(243*time.Second, 260*time.Second)
	return msgs
}

// padded removes the rhythm: every record is padded to the next multiple
// of 256 bytes, so handshakes and keepalives look like data.
func padded(msgs []wgMessage) []wgMessage {
	out := make([]wgMessage, len(msgs))
	for i, m := range msgs {
		m.size = (m.size + wgTLSOverhead + 255) / 256 * 256
		out[i] = m
	}
	return out
}

// wgTLSOverhead is the test transport's: TLS 1.3's AEAD tag and content
// type, and a 2-byte length of its own.
const wgTLSOverhead = 19

// wgRun is a udp-in-TLS-like connection through an engine with the
// rhythm module, on a clock the test moves.
type wgRun struct {
	t                    *testing.T
	eng                  *Engine
	clock                time.Time
	clientSeq, serverSeq uint32
	mss                  int
	actions              []wgAction
}

type wgAction struct {
	at       time.Duration
	toServer bool
	Action
}

func newWGRun(t *testing.T, settings string, mss int) *wgRun {
	t.Helper()
	passives, _, err := Build(Config{Modules: []ModuleConfig{{Name: "wireguard-rhythm", Settings: json.RawMessage(settings)}}})
	if err != nil {
		t.Fatal(err)
	}
	r := &wgRun{t: t, eng: NewEngine(passives, nil, nil), clock: time.Unix(1_700_000_000, 0), mss: mss}
	r.eng.now = func() time.Time { return r.clock }
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1000, 0, Syn, nil))
	r.eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5000, 1001, Syn|Ack, nil))
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1001, 5001, Ack, nil))
	r.clientSeq, r.serverSeq = 1001, 5001
	// The TLS handshake: records the module frames and leaves alone.
	r.send(0, true, tlsRecord(0x16, 512))
	r.send(0, false, append(tlsRecord(0x16, 122), append(tlsRecord(0x14, 1), tlsRecord(0x17, 2048)...)...))
	r.send(0, true, append(tlsRecord(0x14, 1), tlsRecord(0x17, 53)...))
	return r
}

func tlsRecord(typ byte, n int) []byte {
	b := make([]byte, 5+n)
	b[0], b[1], b[2], b[3], b[4] = typ, 3, 3, byte(n>>8), byte(n)
	return b
}

// send writes b one way in segments of at most mss bytes at offset at.
func (r *wgRun) send(at time.Duration, toServer bool, b []byte) {
	r.clock = time.Unix(1_700_000_000, 0).Add(at)
	for len(b) > 0 {
		n := min(r.mss, len(b))
		var p *Packet
		if toServer {
			p = tcpPacket(clientAddr, serverAddr, 40000, 443, r.clientSeq, r.serverSeq, Ack|Psh, b[:n])
			r.clientSeq += uint32(n)
		} else {
			p = tcpPacket(serverAddr, clientAddr, 443, 40000, r.serverSeq, r.clientSeq, Ack|Psh, b[:n])
			r.serverSeq += uint32(n)
		}
		r.actions = append(r.actions, wgAction{at, toServer, r.eng.Handle(p)})
		b = b[n:]
	}
}

// carry sends each message in an application-data record of its own,
// the record its size plus overhead.
func (r *wgRun) carry(msgs []wgMessage, overhead int) { r.carryIn(0x17, msgs, overhead) }

func (r *wgRun) carryIn(typ byte, msgs []wgMessage, overhead int) {
	for _, m := range msgs {
		r.send(m.at, m.toServer, tlsRecord(typ, m.size+overhead))
	}
}

// firstBlocked is the first packet the censor didn't accept, and whether
// there was one.
func (r *wgRun) firstBlocked() (wgAction, bool) {
	for _, a := range r.actions {
		if a.Verdict != Accept {
			return a, true
		}
	}
	return wgAction{}, false
}

// TestWGRhythmFlagsTheRhythm: udp-in-TLS-like traffic with WireGuard's
// rhythm is blocked, both ways, once it shows: on the third keepalive
// record beside the first handshake pair, or, without keepalives, on the
// second rekey pair. Each framing holds: records whole in a segment, and
// records and their headers split over segments.
func TestWGRhythmFlagsTheRhythm(t *testing.T) {
	for _, c := range []struct {
		name       string
		keepalives bool
		wantAt     time.Duration
		wantReason string
	}{
		{"keepalives", true, 85 * time.Second, "keepalives: 3 records of 51 bytes"},
		{"rekey", false, 121*time.Second + 15*time.Millisecond, "rekey: handshake pairs of 167 and 111 bytes 2m1s apart"},
	} {
		for _, mss := range []int{1400, 3} {
			r := newWGRun(t, `{}`, mss)
			r.carry(wgTimeline(c.keepalives), wgTLSOverhead)
			a, blocked := r.firstBlocked()
			if !blocked {
				t.Errorf("%s, mss %d: the rhythm passed", c.name, mss)
				continue
			}
			if a.at != c.wantAt || a.Verdict != Drop || a.Module != "wireguard-rhythm" || !strings.Contains(a.Reason, c.wantReason) {
				t.Errorf("%s, mss %d: first blocked %+v, want a drop at %s for %q", c.name, mss, a, c.wantAt, c.wantReason)
			}
			var accepted [2]int
			for _, later := range r.actions {
				if later.at > a.at && later.Verdict == Accept {
					accepted[map[bool]int{true: 0, false: 1}[later.toServer]]++
				}
			}
			if accepted != [2]int{} {
				t.Errorf("%s, mss %d: after the flag, %d packets to the server and %d to the client passed", c.name, mss, accepted[0], accepted[1])
			}
		}
	}
}

// TestWGRhythmRemovedPasses: the same traffic with the rhythm removed
// (every record padded to a multiple of 256 bytes) passes, as does
// traffic that shows only part of the rhythm.
func TestWGRhythmRemovedPasses(t *testing.T) {
	onePair := []wgMessage{{0, true, wgInitiation}, {15 * time.Millisecond, false, wgResponse}}
	for _, c := range []struct {
		name     string
		msgs     []wgMessage
		overhead int
	}{
		{"padded", padded(wgTimeline(true)), 0},
		// Two keepalives are not yet the rhythm.
		{"one pair, two keepalives", append(onePair, wgMessage{25 * time.Second, true, wgKeepalive}, wgMessage{50 * time.Second, true, wgKeepalive}), wgTLSOverhead},
		// Keepalive-sized records, but of another overhead than the pair's.
		{"keepalives of another overhead", append(onePair, wgMessage{25 * time.Second, true, wgKeepalive + 1}, wgMessage{50 * time.Second, true, wgKeepalive + 1}, wgMessage{75 * time.Second, true, wgKeepalive + 1}), wgTLSOverhead},
		// Pairs a minute apart, or four, are no rekey.
		{"pairs 60 s apart", append(onePair, wgMessage{60 * time.Second, true, wgInitiation}, wgMessage{60*time.Second + 15*time.Millisecond, false, wgResponse}), wgTLSOverhead},
		{"pairs 240 s apart", append(onePair, wgMessage{240 * time.Second, true, wgInitiation}, wgMessage{240*time.Second + 15*time.Millisecond, false, wgResponse}), wgTLSOverhead},
		// A response 3 s after the initiation is no pair.
		{"slow response", []wgMessage{{0, true, wgInitiation}, {3 * time.Second, false, wgResponse}, {121 * time.Second, true, wgInitiation}, {124 * time.Second, false, wgResponse}}, wgTLSOverhead},
		// Both records one way are no pair.
		{"one direction", []wgMessage{{0, true, wgInitiation}, {10 * time.Millisecond, true, wgResponse}, {121 * time.Second, true, wgInitiation}, {121*time.Second + 10*time.Millisecond, true, wgResponse}}, wgTLSOverhead},
	} {
		r := newWGRun(t, `{}`, 1400)
		r.carry(c.msgs, c.overhead)
		if a, blocked := r.firstBlocked(); blocked {
			t.Errorf("%s: blocked at %s: %+v", c.name, a.at, a)
		}
	}
}

// TestWGRhythmNeedsTLS: the rhythm is judged in TLS application-data
// records only: a stream that stops being TLS is never judged again, and
// records of another type don't count.
func TestWGRhythmNeedsTLS(t *testing.T) {
	for name, prefix := range map[string][]byte{
		"HTTP":            []byte("GET / HTTP/1.1\r\n\r\n"),
		"no content type": {0, 3, 3, 0, 0},
		"no TLS version":  {0x17, 2, 0, 0, 0},
		"a later version": {0x17, 3, 5, 0, 0},
		"an unknown type": {0x18, 3, 3, 0, 0},
	} {
		r := newWGRun(t, `{}`, 1400)
		r.send(0, true, prefix)
		r.carry(wgTimeline(true), wgTLSOverhead)
		if a, blocked := r.firstBlocked(); blocked {
			t.Errorf("%s: a stream that isn't TLS was blocked at %s: %+v", name, a.at, a)
		}
	}
	r := newWGRun(t, `{}`, 1400)
	r.carryIn(0x16, wgTimeline(true), wgTLSOverhead)
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("the rhythm in handshake records was blocked at %s: %+v", a.at, a)
	}
}

// TestWGRhythmNewConnection: a new connection on the same addresses and
// ports is judged from its own first record: what the old one showed
// (a handshake pair and two keepalives) adds nothing to it.
func TestWGRhythmNewConnection(t *testing.T) {
	r := newWGRun(t, `{}`, 1400)
	r.carry([]wgMessage{
		{0, true, wgInitiation}, {15 * time.Millisecond, false, wgResponse},
		{25 * time.Second, true, wgKeepalive}, {50 * time.Second, true, wgKeepalive},
	}, wgTLSOverhead)
	r.clock = r.clock.Add(time.Second)
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 90000, 0, Syn, nil))
	r.eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 70000, 90001, Syn|Ack, nil))
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 90001, 70001, Ack, nil))
	r.clientSeq, r.serverSeq = 90001, 70001
	r.send(52*time.Second, true, tlsRecord(0x16, 512))
	r.send(52*time.Second, false, tlsRecord(0x16, 122))
	r.carry([]wgMessage{{75 * time.Second, true, wgKeepalive}}, wgTLSOverhead)
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("the new connection was blocked at %s for the old one's records: %+v", a.at, a)
	}
	// Its own pair and keepalives still show the rhythm.
	r.carry([]wgMessage{
		{80 * time.Second, false, wgInitiation}, {80*time.Second + 15*time.Millisecond, true, wgResponse},
		{100 * time.Second, true, wgKeepalive}, {125 * time.Second, false, wgKeepalive},
	}, wgTLSOverhead)
	if a, blocked := r.firstBlocked(); !blocked || a.at != 125*time.Second {
		t.Errorf("the new connection's own rhythm: first blocked %+v (blocked %v), want at its third keepalive", a, blocked)
	}
}

// TestWGRhythmSettings: a shortened rekey period and a lower keepalive
// count change what shows the rhythm; reset is a verdict too.
func TestWGRhythmSettings(t *testing.T) {
	quick := []wgMessage{
		{0, true, wgInitiation}, {15 * time.Millisecond, false, wgResponse},
		{5 * time.Second, true, wgInitiation}, {5*time.Second + 15*time.Millisecond, false, wgResponse},
	}
	r := newWGRun(t, `{"rekey": "4s", "verdict": "reset"}`, 1400)
	r.carry(quick, wgTLSOverhead)
	if a, blocked := r.firstBlocked(); !blocked || a.Verdict != Reset || a.at != 5*time.Second+15*time.Millisecond {
		t.Errorf("rekey 4s, pairs 5 s apart: first blocked %+v (blocked %v), want a reset at the second pair", a, blocked)
	}

	r = newWGRun(t, `{"keepalives": 1}`, 1400)
	r.carry(append(quick[:2:2], wgMessage{25 * time.Second, true, wgKeepalive}), wgTLSOverhead)
	if a, blocked := r.firstBlocked(); !blocked || a.at != 25*time.Second {
		t.Errorf("keepalives 1: first blocked %+v (blocked %v), want a drop at the first keepalive", a, blocked)
	}

	for settings, wantErr := range map[string]string{
		`{"verdict": "throttle"}`: "verdict",
		`{"rekey": "soon"}`:       "rekey",
		`{"rekey": "1s"}`:         "rekey",
		`{"keepalives": 0}`:       "keepalives",
		`{"verdict": 1}`:          "cannot unmarshal",
	} {
		if _, err := newWGRhythm(json.RawMessage(settings)); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: err %v, want %q", settings, err, wantErr)
		}
	}
}

// TestWGRhythmFramesOnlyWhatItSaw: a stream the module can't frame from
// its first byte is never judged, rhythm or not: one the censor joined
// midstream, and one with bytes the module wasn't shown (a module before
// it dropped their packet, and the stream took them as the receiver
// would have, from the packet the module never saw).
func TestWGRhythmFramesOnlyWhatItSaw(t *testing.T) {
	passives, _, err := Build(Config{Modules: []ModuleConfig{{Name: "wireguard-rhythm", Settings: json.RawMessage(`{}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	r := &wgRun{t: t, eng: NewEngine(passives, nil, nil), clock: time.Unix(1_700_000_000, 0), mss: 1400, clientSeq: 1001, serverSeq: 5001}
	r.eng.now = func() time.Time { return r.clock }
	r.carry(wgTimeline(true), wgTLSOverhead)
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("midstream: blocked at %s: %+v", a.at, a)
	}

	r = newWGRun(t, `{}`, 1400)
	rhythm := r.eng.passives[0]
	r.eng.passives = []Passive{&dropNth{n: 1}, rhythm} // the first handshake initiation
	r.carry(wgTimeline(true), wgTLSOverhead)
	for _, a := range r.actions {
		if a.Module == "wireguard-rhythm" {
			t.Errorf("a stream with bytes the module missed was judged at %s: %+v", a.at, a)
			break
		}
	}
}

// dropNth drops the n-th packet it sees, and only that one.
type dropNth struct{ n, saw int }

func (m *dropNth) Name() string { return "drop-one" }

func (m *dropNth) Inspect(*Packet, *Flow) Decision {
	if m.saw++; m.saw == m.n {
		return Decision{Verdict: Drop}
	}
	return Decision{Verdict: Accept}
}
