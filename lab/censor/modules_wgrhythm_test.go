package censor

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// wgKeepalive is a WireGuard keepalive's size: a transport message with
// nothing in it.
const wgKeepalive = 32

// wgMessage is one WireGuard message a udp-in-TLS-like transport carries:
// at offset into the run, from the client or the server, size bytes
// before the transport's overhead.
type wgMessage struct {
	at       time.Duration
	toServer bool
	size     int
}

// wireRecord is one TLS application-data record on the wire: at offset
// into the run, from the client or the server, size its length field.
type wireRecord struct {
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

// busy adds to msgs a tunnel busy sending around each initiation the
// client sends: 1200-byte messages every 250 µs from 100 ms before it to
// 100 ms after.
func busy(msgs []wgMessage) []wgMessage {
	out := slices.Clone(msgs)
	for _, m := range msgs {
		if !m.toServer || m.size != wgInitiation {
			continue
		}
		for at := m.at - 100*time.Millisecond; at < m.at+100*time.Millisecond; at += 250 * time.Microsecond {
			if at >= 0 {
				out = append(out, wgMessage{at, true, 1200})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b wgMessage) int { return int(a.at - b.at) })
	return out
}

// wgTLSOverhead is the test transport's: TLS 1.3's AEAD tag and content
// type, and a 2-byte length of its own.
const wgTLSOverhead = 19

// eachInRecord carries each message in a record of its own, of the size
// recordSize gives it.
func eachInRecord(msgs []wgMessage, recordSize func(wgMessage) int) []wireRecord {
	out := make([]wireRecord, len(msgs))
	for i, m := range msgs {
		out[i] = wireRecord{m.at, m.toServer, recordSize(m)}
	}
	return out
}

func withOverhead(n int) func(wgMessage) int {
	return func(m wgMessage) int { return m.size + n }
}

// paddedTo pads the message and its 2-byte length to a multiple of n,
// inside the record's 17 bytes of AEAD tag and content type.
func paddedTo(n int) func(wgMessage) int {
	return func(m wgMessage) int { return (m.size+2+n-1)/n*n + 17 }
}

// perDirection adds one overhead to the client's messages and another to
// the server's.
func perDirection(client, server int) func(wgMessage) int {
	return func(m wgMessage) int {
		if m.toServer {
			return m.size + client
		}
		return m.size + server
	}
}

// batched carries the messages through a batching window: each direction
// sends what it got within window of the first message in one record,
// every message with its 2-byte length, when the window closes.
func batched(msgs []wgMessage, window time.Duration) []wireRecord {
	var out []wireRecord
	var open [2]*wireRecord
	flush := func(dir int) {
		if open[dir] != nil {
			open[dir].size += 17
			open[dir].at += window
			out = append(out, *open[dir])
			open[dir] = nil
		}
	}
	for _, m := range msgs {
		dir := map[bool]int{true: 0, false: 1}[m.toServer]
		if open[dir] != nil && m.at >= open[dir].at+window {
			flush(dir)
		}
		if open[dir] == nil {
			open[dir] = &wireRecord{m.at, m.toServer, 0}
		}
		open[dir].size += m.size + 2
	}
	flush(0)
	flush(1)
	slices.SortStableFunc(out, func(a, b wireRecord) int { return int(a.at - b.at) })
	return out
}

// lengthPrefixed writes each message's 2-byte length as a record of its
// own, the message in the next.
func lengthPrefixed(msgs []wgMessage) []wireRecord {
	var out []wireRecord
	for _, m := range msgs {
		out = append(out, wireRecord{m.at, m.toServer, 2 + 17}, wireRecord{m.at, m.toServer, m.size + 17})
	}
	return out
}

// wgRun is a udp-in-TLS-like connection through an engine with the
// rhythm module, on a clock the test moves.
type wgRun struct {
	eng                  *Engine
	log                  bytes.Buffer
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
	r := newWGEngine(t, settings, mss)
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1000, 0, Syn, nil))
	r.eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 5000, 1001, Syn|Ack, nil))
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 1001, 5001, Ack, nil))
	// The TLS handshake: records the module frames and leaves alone.
	r.send(0, true, tlsRecord(0x16, 512))
	r.send(0, false, append(tlsRecord(0x16, 122), append(tlsRecord(0x14, 1), tlsRecord(0x17, 2048)...)...))
	r.send(0, true, append(tlsRecord(0x14, 1), tlsRecord(0x17, 53)...))
	return r
}

// newWGEngine is an engine with only the rhythm module, and no
// connection yet.
func newWGEngine(t *testing.T, settings string, mss int) *wgRun {
	t.Helper()
	passives, _, err := Build(Config{Modules: []ModuleConfig{{Name: "wireguard-rhythm", Settings: json.RawMessage(settings)}}})
	if err != nil {
		t.Fatal(err)
	}
	r := &wgRun{clock: time.Unix(1_700_000_000, 0), mss: mss, clientSeq: 1001, serverSeq: 5001}
	r.eng = NewEngine(passives, nil, &r.log)
	r.eng.now = func() time.Time { return r.clock }
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

// carryIn sends each record as a TLS record of type typ.
func (r *wgRun) carryIn(typ byte, recs []wireRecord) {
	for _, w := range recs {
		r.send(w.at, w.toServer, tlsRecord(typ, w.size))
	}
}

// carry sends each record as an application-data record.
func (r *wgRun) carry(recs []wireRecord) { r.carryIn(0x17, recs) }

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

// tags shuts the engine down and returns the tags the rhythm module put on
// flows, by flow.
func (r *wgRun) tags(t *testing.T) map[string][]string {
	t.Helper()
	r.eng.Shutdown()
	tags := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(r.log.String()), "\n") {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Event == EventTag && e.Module == "wireguard-rhythm" {
			tags[e.Flow] = append(tags[e.Flow], e.Reason)
		}
	}
	return tags
}

const (
	wgRekeyAt     = 242*time.Second + 15*time.Millisecond // the third handshake's response
	wgKeepaliveAt = 85 * time.Second                      // the third idle keepalive
)

// TestWGRhythmFlagsTheRhythm: udp-in-TLS-like traffic with WireGuard's
// rhythm is blocked, both ways, once it shows: on the third idle
// keepalive, or, without keepalives, on the third handshake a rekey period
// after the one before. Neither signal reads WireGuard's exact sizes: it
// holds through padding to 16 or 256 bytes (sizes hidden, rhythm kept),
// another overhead each way, a busy tunnel around each rekey, a batching
// window, and lengths written as records of their own. Each framing
// holds: records whole in a segment, and records and their headers split
// over segments.
func TestWGRhythmFlagsTheRhythm(t *testing.T) {
	plain := withOverhead(wgTLSOverhead)
	for _, c := range []struct {
		name       string
		recs       []wireRecord
		wantAt     time.Duration
		wantReason string
		splitToo   bool
	}{
		{"keepalives", eachInRecord(wgTimeline(true), plain), wgKeepaliveAt,
			"keepalives: 3 idle records of 51 bytes, 25s apart", true},
		{"rekey", eachInRecord(wgTimeline(false), plain), wgRekeyAt,
			"rekey: records of 167 and 111 bytes exchanged 3 times, the last 2m1s apart", true},
		{"padded to 16, keepalives", eachInRecord(wgTimeline(true), paddedTo(16)), wgKeepaliveAt, "of 65 bytes", false},
		{"padded to 16, rekey", eachInRecord(wgTimeline(false), paddedTo(16)), wgRekeyAt, "records of 177 and 113 bytes", false},
		{"sizes hidden, keepalives kept", eachInRecord(wgTimeline(true), paddedTo(256)), wgKeepaliveAt, "of 273 bytes", false},
		{"sizes hidden, rekey kept", eachInRecord(wgTimeline(false), paddedTo(256)), wgRekeyAt, "records of 273 and 273 bytes", false},
		{"overhead per direction", eachInRecord(wgTimeline(false), perDirection(19, 40)), wgRekeyAt, "records of 167 and 132 bytes", false},
		{"busy around each rekey", eachInRecord(busy(wgTimeline(false)), plain), wgRekeyAt, "records of 167 and 111 bytes", false},
		// Through a 20 ms batching window idle messages still travel
		// alone.
		{"batched, keepalives", batched(wgTimeline(true), 20*time.Millisecond), wgKeepaliveAt + 20*time.Millisecond, "of 51 bytes", false},
		{"batched, rekey", batched(wgTimeline(false), 20*time.Millisecond), wgRekeyAt + 20*time.Millisecond, "records of 167 and 111 bytes", false},
		{"length prefixed, keepalives", lengthPrefixed(wgTimeline(true)), wgKeepaliveAt, "of 19 bytes", false},
		{"length prefixed, rekey", lengthPrefixed(wgTimeline(false)), wgRekeyAt, "records of 165 and 109 bytes", false},
	} {
		mssList := []int{1400}
		if c.splitToo {
			mssList = append(mssList, 3)
		}
		for _, mss := range mssList {
			r := newWGRun(t, `{}`, mss)
			r.carry(c.recs)
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

// TestWGRhythmCoalescedHandshakeUnderLoad pins a known miss (lab/censor's
// package doc): through a batching window, a handshake message sent while
// the tunnel is busy shares a record with data, leaves the handshake band,
// and the rekey goes unseen. Idle keepalives would still show.
func TestWGRhythmCoalescedHandshakeUnderLoad(t *testing.T) {
	r := newWGRun(t, `{}`, 1400)
	r.carry(batched(busy(wgTimeline(false)), 20*time.Millisecond))
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("blocked at %s: %+v; if the module now sees this, update the package doc", a.at, a)
	}
}

// jittered removes the rhythm: every record padded by a random amount up
// to 255 bytes, and each idle keepalive moved by up to 10 s either way, so
// no size recurs at a steady interval and no exchange recurs.
func jittered(msgs []wgMessage, rng *rand.Rand) []wireRecord {
	out := make([]wireRecord, len(msgs))
	for i, m := range msgs {
		at := m.at
		if m.size == wgKeepalive {
			at += time.Duration(rng.IntN(20_000)-10_000) * time.Millisecond
		}
		out[i] = wireRecord{at, m.toServer, m.size + wgTLSOverhead + rng.IntN(256)}
	}
	slices.SortStableFunc(out, func(a, b wireRecord) int { return int(a.at - b.at) })
	return out
}

// TestWGRhythmRemovedPasses: the same traffic with the rhythm removed
// (sizes and idle timing jittered) passes, as does traffic that shows only
// part of the rhythm.
func TestWGRhythmRemovedPasses(t *testing.T) {
	for seed := range uint64(20) {
		r := newWGRun(t, `{}`, 1400)
		r.carry(jittered(wgTimeline(true), rand.New(rand.NewPCG(seed, 188))))
		if a, blocked := r.firstBlocked(); blocked {
			t.Errorf("jittered, seed %d: blocked at %s: %+v", seed, a.at, a)
		}
	}
	pair := func(at time.Duration, toServer bool) []wgMessage {
		return []wgMessage{{at, toServer, wgInitiation}, {at + 15*time.Millisecond, !toServer, wgResponse}}
	}
	idle := func(toServer bool, at ...time.Duration) []wgMessage {
		var out []wgMessage
		for _, a := range at {
			out = append(out, wgMessage{a, toServer, wgKeepalive})
		}
		return out
	}
	s := time.Second
	for _, c := range []struct {
		name string
		msgs []wgMessage
	}{
		// Two rekeys are not yet the rhythm.
		{"two pairs a rekey apart", slices.Concat(pair(0, true), pair(121*s, true))},
		{"three pairs 60 s apart", slices.Concat(pair(0, true), pair(60*s, true), pair(120*s, true))},
		{"three pairs 240 s apart", slices.Concat(pair(0, true), pair(240*s, true), pair(480*s, true))},
		// An answer 3 s later is no exchange.
		{"slow answers", []wgMessage{
			{0, true, wgInitiation}, {3 * s, false, wgResponse},
			{121 * s, true, wgInitiation}, {124 * s, false, wgResponse},
			{242 * s, true, wgInitiation}, {245 * s, false, wgResponse},
		}},
		{"one direction", []wgMessage{
			{0, true, wgInitiation}, {10 * time.Millisecond, true, wgResponse},
			{121 * s, true, wgInitiation}, {121*s + 10*time.Millisecond, true, wgResponse},
			{242 * s, true, wgInitiation}, {242*s + 10*time.Millisecond, true, wgResponse},
		}},
		{"a pair, two keepalives", slices.Concat(pair(0, true), idle(true, 25*s, 50*s))},
		{"a pair, keepalives at no steady interval", slices.Concat(pair(0, true), idle(true, 25*s, 50*s, 85*s, 110*s, 150*s))},
		// Records sent every 3 s are a stream, never idle.
		{"a pair, a steady stream", slices.Concat(pair(0, true), idle(true, 3*s, 6*s, 9*s, 12*s, 15*s, 18*s))},
		// Answered within the pair window, like an HTTP/2 PING.
		{"a pair, answered keepalives", slices.Concat(pair(0, true),
			idle(true, 25*s, 50*s, 75*s, 100*s), idle(false, 25*s+30*time.Millisecond, 50*s+30*time.Millisecond, 75*s+30*time.Millisecond, 100*s+30*time.Millisecond))},
		// Without an exchange, four idle records are not yet a steady
		// idle period.
		{"four keepalives, no exchange", idle(true, 25*s, 50*s, 75*s, 100*s)},
	} {
		msgs := slices.Clone(c.msgs)
		slices.SortStableFunc(msgs, func(a, b wgMessage) int { return int(a.at - b.at) })
		r := newWGRun(t, `{}`, 1400)
		r.carry(eachInRecord(msgs, withOverhead(wgTLSOverhead)))
		if a, blocked := r.firstBlocked(); blocked {
			t.Errorf("%s: blocked at %s: %+v", c.name, a.at, a)
		}
	}
}

// TestWGRhythmSteadyIdlePeriodAlone: without any exchange in the
// handshake band, an idle run shows the rhythm at its fifth record.
func TestWGRhythmSteadyIdlePeriodAlone(t *testing.T) {
	r := newWGRun(t, `{}`, 1400)
	var msgs []wgMessage
	for at := 25 * time.Second; at <= 150*time.Second; at += 25 * time.Second {
		msgs = append(msgs, wgMessage{at, true, wgKeepalive})
	}
	r.carry(eachInRecord(msgs, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != 125*time.Second || !strings.Contains(a.Reason, "5 idle records") {
		t.Errorf("first blocked %+v (blocked %v), want a drop at the fifth keepalive, 125 s", a, blocked)
	}
}

// TestWGRhythmOrdinaryTLS: realistic shapes of ordinary TLS pass, except
// the false-positive risks the package doc names, which are pinned here so
// a change to them is seen.
func TestWGRhythmOrdinaryTLS(t *testing.T) {
	s, ms := time.Second, time.Millisecond
	rng := rand.New(rand.NewPCG(1, 188))
	rec := func(at time.Duration, toServer bool, size int) wireRecord { return wireRecord{at, toServer, size} }
	// HTTP/2 over TLS 1.3, sizes with the record's 17 bytes: the client's
	// preface and SETTINGS, the server's SETTINGS and the acks.
	h2Start := []wireRecord{rec(0, true, 81), rec(30*ms, false, 44), rec(31*ms, false, 26), rec(60*ms, true, 26)}

	var browse []wireRecord
	browse = append(browse, h2Start...)
	for p, load := range []time.Duration{1 * s, 70 * s, 190 * s, 300 * s} {
		for k := range 8 {
			at := load + time.Duration(k)*50*ms
			browse = append(browse, rec(at, true, 60+(p*37+k*23)%150))
			resp := 200 + (p*131+k*97)%3000
			for resp > 16401 {
				browse = append(browse, rec(at+80*ms, false, 16401))
				resp -= 16401
			}
			browse = append(browse, rec(at+80*ms, false, resp))
		}
		// Idle: the server PINGs every 45 s, the client answers.
		for at := load + 45*s; at < load+110*s; at += 45 * s {
			browse = append(browse, rec(at, false, 34), rec(at+30*ms, true, 34))
		}
	}

	var grpc []wireRecord
	grpc = append(grpc, h2Start...)
	grpc = append(grpc, rec(100*ms, true, 140), rec(101*ms, true, 77), rec(150*ms, false, 95))
	for at := 2 * s; at < 360*s; at += time.Duration(5+rng.IntN(55)) * s {
		grpc = append(grpc, rec(at, false, 60+rng.IntN(900)))
	}
	for at := 20 * s; at < 360*s; at += 20 * s {
		grpc = append(grpc, rec(at, true, 34), rec(at+25*ms, false, 34))
	}

	var download []wireRecord
	download = append(download, h2Start...)
	download = append(download, rec(100*ms, true, 150), rec(150*ms, false, 120))
	for at, i := 200*ms, 0; at < 10*s; at, i = at+2*ms, i+1 {
		download = append(download, rec(at, false, 16401))
		if i%4 == 3 {
			download = append(download, rec(at+ms, true, 30))
		}
	}

	poll := func(every time.Duration, req int, resp ...int) []wireRecord {
		var out []wireRecord
		for at := time.Duration(0); at < 600*s; at += every + time.Duration(rng.IntN(500))*ms {
			out = append(out, rec(at, true, req))
			for i, n := range resp {
				out = append(out, rec(at+40*ms+time.Duration(i)*ms, false, n))
			}
		}
		return out
	}
	var h2Poll []wireRecord
	h2Poll = append(h2Poll, h2Start...)
	for _, w := range poll(120*s, 45, 60, 140) {
		w.at += s
		h2Poll = append(h2Poll, w)
	}

	sse := []wireRecord{rec(0, true, 280), rec(50*ms, false, 190)}
	for at := 15 * s; at < 120*s; at += 15 * s {
		sse = append(sse, rec(at, false, 25))
	}

	for _, c := range []struct {
		name string
		recs []wireRecord
		// flaggedAt is when a named false-positive risk is flagged, 0 for
		// a shape that passes.
		flaggedAt time.Duration
	}{
		{"HTTP/2 browsing, idle PINGs", browse, 0},
		{"gRPC stream with keepalive PINGs", grpc, 0},
		{"bulk download", download, 0},
		{"HTTP/2 poll every 2 minutes", h2Poll, 0},
		// Risk: an identical request and response, both in the handshake
		// band, repeated for four minutes at any interval up to three.
		{"HTTP/1.1 poll every 2 minutes", poll(120*s, 260, 380), -1},
		{"HTTP/1.1 poll every 30 s", poll(30*s, 260, 380), -1},
		// Risk: a server heartbeat, one unanswered record of one size at a
		// steady idle interval (a server-sent events comment line).
		{"server-sent events heartbeat", sse, 45 * s},
	} {
		recs := slices.Clone(c.recs)
		slices.SortStableFunc(recs, func(a, b wireRecord) int { return int(a.at - b.at) })
		r := newWGRun(t, `{}`, 1400)
		r.carry(recs)
		a, blocked := r.firstBlocked()
		switch {
		case c.flaggedAt == 0 && blocked:
			t.Errorf("%s: blocked at %s: %+v", c.name, a.at, a)
		case c.flaggedAt != 0 && !blocked:
			t.Errorf("%s: passed; a named false-positive risk is gone, update the package doc", c.name)
		case c.flaggedAt > 0 && a.at != c.flaggedAt:
			t.Errorf("%s: blocked at %s, want %s", c.name, a.at, c.flaggedAt)
		case c.flaggedAt < 0 && a.at < 240*s:
			t.Errorf("%s: blocked at %s, before the third poll a rekey period apart", c.name, a.at)
		}
	}
}

// TestWGRhythmBadChecksum: a segment with a bad checksum (a decoy the
// receiver discards) leaves the framing alone: the rhythm after it is
// still flagged.
func TestWGRhythmBadChecksum(t *testing.T) {
	r := newWGRun(t, `{}`, 1400)
	decoy := tcpPacket(clientAddr, serverAddr, 40000, 443, r.clientSeq, r.serverSeq, Ack|Psh, bytes.Repeat([]byte("d"), 100))
	decoy.BadChecksum = true
	r.eng.Handle(decoy)
	r.carry(eachInRecord(wgTimeline(true), withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != wgKeepaliveAt {
		t.Errorf("first blocked %+v (blocked %v), want a drop at %s", a, blocked, wgKeepaliveAt)
	}
}

// TestWGRhythmNeedsTLS: the rhythm is judged in TLS application-data
// records only: a stream that stops being TLS is never judged again, and
// is tagged once as not framed; records of another type don't count.
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
		r.carry(eachInRecord(wgTimeline(true), withOverhead(wgTLSOverhead)))
		if a, blocked := r.firstBlocked(); blocked {
			t.Errorf("%s: a stream that isn't TLS was blocked at %s: %+v", name, a.at, a)
		}
		want := map[string][]string{"tcp 192.0.2.1:40000->203.0.113.9:443": {"wireguard-rhythm: stream not framed"}}
		if got := r.tags(t); !equalTags(got, want) {
			t.Errorf("%s: tags %v, want %v", name, got, want)
		}
	}
	r := newWGRun(t, `{}`, 1400)
	r.carryIn(0x16, eachInRecord(wgTimeline(true), withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("the rhythm in handshake records was blocked at %s: %+v", a.at, a)
	}
	if got := r.tags(t); len(got) != 0 {
		t.Errorf("a framed stream was tagged: %v", got)
	}
}

func equalTags(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// TestWGRhythmNewConnection: a new connection on the same addresses and
// ports is judged from its own first record: what the old one showed (a
// handshake pair and two keepalives) adds nothing to it.
func TestWGRhythmNewConnection(t *testing.T) {
	s := time.Second
	r := newWGRun(t, `{}`, 1400)
	r.carry(eachInRecord([]wgMessage{
		{0, true, wgInitiation}, {15 * time.Millisecond, false, wgResponse},
		{25 * s, true, wgKeepalive}, {50 * s, true, wgKeepalive},
	}, withOverhead(wgTLSOverhead)))
	r.clock = r.clock.Add(s)
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 90000, 0, Syn, nil))
	r.eng.Handle(tcpPacket(serverAddr, clientAddr, 443, 40000, 70000, 90001, Syn|Ack, nil))
	r.eng.Handle(tcpPacket(clientAddr, serverAddr, 40000, 443, 90001, 70001, Ack, nil))
	r.clientSeq, r.serverSeq = 90001, 70001
	r.send(52*s, true, tlsRecord(0x16, 512))
	r.send(52*s, false, tlsRecord(0x16, 122))
	r.carry(eachInRecord([]wgMessage{{75 * s, true, wgKeepalive}}, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("the new connection was blocked at %s for the old one's records: %+v", a.at, a)
	}
	// Its own pair and keepalives still show the rhythm.
	r.carry(eachInRecord([]wgMessage{
		{80 * s, false, wgInitiation}, {80*s + 15*time.Millisecond, true, wgResponse},
		{100 * s, true, wgKeepalive}, {125 * s, false, wgKeepalive}, {150 * s, true, wgKeepalive},
	}, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != 150*s {
		t.Errorf("the new connection's own rhythm: first blocked %+v (blocked %v), want at its third keepalive", a, blocked)
	}
}

// TestWGRhythmSettings: a shortened rekey period and a lower keepalive
// count change what shows the rhythm; reset is a verdict too.
func TestWGRhythmSettings(t *testing.T) {
	s := time.Second
	var quick []wgMessage
	for _, at := range []time.Duration{0, 5 * s, 10 * s} {
		quick = append(quick, wgMessage{at, true, wgInitiation}, wgMessage{at + 15*time.Millisecond, false, wgResponse})
	}
	r := newWGRun(t, `{"rekey": "4s", "verdict": "reset"}`, 1400)
	r.carry(eachInRecord(quick, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.Verdict != Reset || a.at != 10*s+15*time.Millisecond {
		t.Errorf("rekey 4s, pairs 5 s apart: first blocked %+v (blocked %v), want a reset at the third pair", a, blocked)
	}

	r = newWGRun(t, `{"keepalives": 1}`, 1400)
	r.carry(eachInRecord(append(quick[:2:2], wgMessage{25 * s, true, wgKeepalive}), withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != 25*s {
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
	r := newWGEngine(t, `{}`, 1400)
	r.carry(eachInRecord(wgTimeline(true), withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("midstream: blocked at %s: %+v", a.at, a)
	}

	r = newWGRun(t, `{}`, 1400)
	rhythm := r.eng.passives[0]
	r.eng.passives = []Passive{&dropNth{n: 1}, rhythm} // the first handshake initiation
	r.carry(eachInRecord(wgTimeline(true), withOverhead(wgTLSOverhead)))
	for _, a := range r.actions {
		if a.Module == "wireguard-rhythm" {
			t.Errorf("a stream with bytes the module missed was judged at %s: %+v", a.at, a)
			break
		}
	}
}

// dropNth drops the n-th packet it sees, and only that one.
type dropNth struct{ n, saw int }

func (m *dropNth) Name() string { return "drop-nth" }

func (m *dropNth) Inspect(*Packet, *Flow) Decision {
	if m.saw++; m.saw == m.n {
		return Decision{Verdict: Drop}
	}
	return Decision{Verdict: Accept}
}
