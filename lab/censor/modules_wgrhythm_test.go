package censor

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	idle := func(from, to time.Duration) {
		for at := from + 25*time.Second; keepalives && at < to; at += 25 * time.Second {
			msgs = append(msgs, wgMessage{at, true, wgKeepalive})
		}
	}
	msgs = append(msgs, wgHandshake(0)...)
	msgs = append(msgs, wgBurst(time.Second, 11*time.Second, 0)...)
	idle(10*time.Second, 121*time.Second)
	msgs = append(msgs, wgHandshake(121*time.Second)...)
	msgs = append(msgs, wgBurst(122*time.Second, 131*time.Second, 0)...)
	idle(130*time.Second, 242*time.Second)
	msgs = append(msgs, wgHandshake(242*time.Second)...)
	msgs = append(msgs, wgBurst(243*time.Second, 260*time.Second, 0)...)
	return msgs
}

// wgHandshake is a handshake the client starts at at.
func wgHandshake(at time.Duration) []wgMessage {
	return []wgMessage{{at, true, wgInitiation}, {at + 15*time.Millisecond, false, wgResponse}}
}

// wgBurst is data each way every second from from to to, its sizes picked
// from shift on.
func wgBurst(from, to time.Duration, shift int) []wgMessage {
	var msgs []wgMessage
	for at, i := from, shift; at < to; at, i = at+time.Second, i+1 {
		msgs = append(msgs,
			wgMessage{at, true, wgKeepalive + 16*(1+i%60)},
			wgMessage{at + 20*time.Millisecond, false, wgKeepalive + 16*(1+(i*7)%80)})
	}
	return msgs
}

// wgRekeyTimeline is a tunnel that rekeys as WireGuard does, on the first
// packet it sends past the deadline: the first handshake, then after each
// gap a message of the size trigger gives (a keepalive or data) and, 500
// µs later, the initiation; a burst of data after each handshake, of other
// sizes each time; no idle keepalives.
func wgRekeyTimeline(trigger func(i int) int, gaps ...time.Duration) []wgMessage {
	msgs := slices.Concat(wgHandshake(0), wgBurst(time.Second, 11*time.Second, 0))
	at := time.Duration(0)
	for i, gap := range gaps {
		at += gap
		msgs = append(msgs, wgMessage{at - 500*time.Microsecond, true, trigger(i)})
		msgs = append(msgs, wgHandshake(at)...)
		msgs = append(msgs, wgBurst(at+time.Second, at+11*time.Second, 11*(i+1))...)
	}
	return msgs
}

// keepaliveTrigger and dataTrigger are what the client sends just before
// each rekey's initiation: a keepalive, or data of another size each time.
func keepaliveTrigger(int) int { return wgKeepalive }
func dataTrigger(i int) int    { return wgKeepalive + 16*(3+5*i) }

// wgLateRekeyAt is when the third handshake of a rekey timeline 125 s and
// 190 s apart is answered.
const wgLateRekeyAt = 315*time.Second + 15*time.Millisecond

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

func newWGRun(t testing.TB, settings string, mss int) *wgRun {
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
func newWGEngine(t testing.TB, settings string, mss int) *wgRun {
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
	wgRekeyAt = 242*time.Second + 15*time.Millisecond // the third handshake's response
	// the fourth idle keepalive: the first packet after the third's answer
	// window closed
	wgKeepaliveAt = 110 * time.Second
)

// TestWGRhythmFlagsTheRhythm: udp-in-TLS-like traffic with WireGuard's
// rhythm is blocked, both ways, once it shows: on the first packet after
// the third idle keepalive's answer window, or, without keepalives, on the
// third handshake a rekey period after the one before, a rekey triggered by
// a packet too, gaps of 125 s and 190 s too. Neither signal reads WireGuard's exact sizes: it
// holds through padding to 16 or 256 bytes (sizes hidden, rhythm kept),
// another overhead each way, a busy tunnel around each rekey, a batching
// window, and lengths written as records of their own. Each framing
// holds: records whole in a segment, and records and their headers split
// over segments.
func TestWGRhythmFlagsTheRhythm(t *testing.T) {
	s := time.Second
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
		{"rekey after a keepalive, 125 s and 190 s apart", eachInRecord(wgRekeyTimeline(keepaliveTrigger, 125*s, 190*s), plain),
			wgLateRekeyAt, "records of 167 and 111 bytes exchanged 3 times, the last 3m10s apart", true},
		{"rekey after data, 125 s and 190 s apart", eachInRecord(wgRekeyTimeline(dataTrigger, 125*s, 190*s), plain),
			wgLateRekeyAt, "records of 167 and 111 bytes", false},
		// Padded to 256 the trigger is the initiation's size: the two are
		// one band record that stands out.
		{"sizes hidden, rekey after a keepalive, 125 s and 190 s apart", eachInRecord(wgRekeyTimeline(keepaliveTrigger, 125*s, 190*s), paddedTo(256)),
			wgLateRekeyAt, "records of 273 and 273 bytes exchanged 3 times, the last 3m10s apart", true},
		{"sizes hidden, rekey after data, 125 s and 190 s apart", eachInRecord(wgRekeyTimeline(dataTrigger, 125*s, 190*s), paddedTo(256)),
			wgLateRekeyAt, "records of 273 and 273 bytes exchanged 3 times", false},
		// Through a 20 ms batching window idle keepalives still travel
		// alone, and an initiation shares a record with the keepalive that
		// triggered it: a record of one size each time.
		{"batched, keepalives", batched(wgTimeline(true), 20*time.Millisecond), wgKeepaliveAt + 20*time.Millisecond, "of 51 bytes", false},
		// The first handshake has no trigger: the third of one size is the
		// fourth.
		{"batched, rekey after a keepalive", batched(wgRekeyTimeline(keepaliveTrigger, 125*s, 190*s, 125*s), 20*time.Millisecond),
			440*s + 35*time.Millisecond, "records of 201 and 111 bytes exchanged 3 times", false},
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

// TestWGRhythmStandsOutLateInAnOccurrence: an exchange's occurrence that
// didn't stand out at its first answer stands out when a later answer
// within wgPairWindow does. Each time, the server's 200 bytes are answered
// by the client's 300, neither new, and 700 µs later the client's 200,
// new, by the server's 300, new: one occurrence of the 200/300 exchange,
// standing out at its second answer, three times 130 s apart. The other
// records keep the 200/300 records from following quiet and answer the
// idle ones.
func TestWGRhythmStandsOutLateInAnOccurrence(t *testing.T) {
	ms := time.Millisecond
	var recs []wireRecord
	for _, at := range []time.Duration{20 * time.Second, 150 * time.Second, 280 * time.Second} {
		recs = append(recs,
			wireRecord{at - 10000*ms, false, 200},
			wireRecord{at - 9900*ms, true, 1000},
			wireRecord{at - 4500*ms, true, 300},
			wireRecord{at - 4400*ms, false, 1000},
			wireRecord{at - 1000*ms, false, 200},
			wireRecord{at - 500*ms, true, 300},
			wireRecord{at - 300*ms, true, 200},
			wireRecord{at, false, 300})
	}
	r := newWGRun(t, `{}`, 1400)
	r.carry(recs)
	a, blocked := r.firstBlocked()
	if !blocked || a.at != 280*time.Second || !strings.Contains(a.Reason, "records of 200 and 300 bytes exchanged 3 times") {
		t.Errorf("first blocked %+v (blocked %v), want a drop at 4m40s for the 200/300 exchange", a, blocked)
	}
}

// TestWGRhythmPaddedTriggerAfterBandTraffic: a padded rekey whose trigger
// is the initiation's size and follows other band traffic within wgQuiet
// stands out by freshness alone, which the initiation takes from the
// trigger: a client record of 150 bytes (answered out of the band) 3 s
// before each trigger, rekeys 125 s and 190 s apart.
func TestWGRhythmPaddedTriggerAfterBandTraffic(t *testing.T) {
	ms := time.Millisecond
	var recs []wireRecord
	for _, at := range []time.Duration{10 * time.Second, 135 * time.Second, 325 * time.Second} {
		recs = append(recs,
			wireRecord{at - 3000*ms, true, 150},
			wireRecord{at - 2900*ms, false, 1000},
			wireRecord{at - ms/2, true, 273},
			wireRecord{at, true, 273},
			wireRecord{at + 15*ms, false, 273})
	}
	r := newWGRun(t, `{}`, 1400)
	r.carry(recs)
	want := 325*time.Second + 15*ms
	a, blocked := r.firstBlocked()
	if !blocked || a.at != want || !strings.Contains(a.Reason, "records of 273 and 273 bytes exchanged 3 times") {
		t.Errorf("first blocked %+v (blocked %v), want a drop at %s for the 273/273 exchange", a, blocked, want)
	}
}

// TestWGRhythmStaleBandRecordLendsNothing: only a record of the same size
// within wgPairWindow lends its standing out. Each 130 s the client's 200
// bytes follow quiet 60 s before its 200-byte exchange, which is neither
// new nor after quiet (a 300-byte record 3 s before it): no rekey. The
// out-of-band records answer the idle ones.
func TestWGRhythmStaleBandRecordLendsNothing(t *testing.T) {
	ms := time.Millisecond
	var recs []wireRecord
	for at := 70 * time.Second; at < 600*time.Second; at += 130 * time.Second {
		recs = append(recs,
			wireRecord{at - 60000*ms, true, 200},
			wireRecord{at - 59900*ms, false, 1000},
			wireRecord{at - 3000*ms, true, 300},
			wireRecord{at - 2900*ms, false, 1000},
			wireRecord{at - 500*ms, true, 200},
			wireRecord{at, false, 200})
	}
	r := newWGRun(t, `{}`, 1400)
	r.carry(recs)
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("blocked at %s: %+v", a.at, a)
	}
}

// TestWGRhythmCoalescedHandshakeUnderLoad pins known misses (lab/censor's
// package doc): through a batching window an initiation shares a record
// with the packet that triggered it, so when that is data of another size
// each time, or the tunnel is busy, the rekey goes unseen. Idle keepalives
// would still show.
func TestWGRhythmCoalescedHandshakeUnderLoad(t *testing.T) {
	s := time.Second
	for name, msgs := range map[string][]wgMessage{
		"busy":                           busy(wgTimeline(false)),
		"triggered by data":              wgRekeyTimeline(dataTrigger, 125*s, 190*s),
		"triggered by a keepalive, busy": busy(wgRekeyTimeline(keepaliveTrigger, 125*s, 190*s)),
	} {
		r := newWGRun(t, `{}`, 1400)
		r.carry(batched(msgs, 20*time.Millisecond))
		if a, blocked := r.firstBlocked(); blocked {
			t.Errorf("%s: blocked at %s: %+v; if the module now sees this, update the package doc", name, a.at, a)
		}
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
// handshake band, an idle run shows the rhythm at its fifth record, once
// its answer window has passed: on the sixth.
func TestWGRhythmSteadyIdlePeriodAlone(t *testing.T) {
	r := newWGRun(t, `{}`, 1400)
	var msgs []wgMessage
	for at := 25 * time.Second; at <= 150*time.Second; at += 25 * time.Second {
		msgs = append(msgs, wgMessage{at, true, wgKeepalive})
	}
	r.carry(eachInRecord(msgs, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != 150*time.Second || !strings.Contains(a.Reason, "5 idle records") {
		t.Errorf("first blocked %+v (blocked %v), want a drop for five keepalives at the sixth, 150 s", a, blocked)
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
		// An identical request and response, both in the handshake band,
		// at a steady interval shorter than a rekey period never stands
		// out a rekey period after it last did.
		{"HTTP/1.1 poll every 30 s", poll(30*s, 260, 380), 0},
		// Risk: the same at an interval within the rekey window.
		{"HTTP/1.1 poll every 2 minutes", poll(120*s, 260, 380), -1},
		// Risk: a server heartbeat, one unanswered record of one size at a
		// steady idle interval (a server-sent events comment line), flagged
		// at the record after the third.
		{"server-sent events heartbeat", sse, 60 * s},
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
		{100 * s, true, wgKeepalive}, {125 * s, false, wgKeepalive}, {150 * s, true, wgKeepalive}, {175 * s, true, wgKeepalive},
	}, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != 175*s {
		t.Errorf("the new connection's own rhythm: first blocked %+v (blocked %v), want at the record after its third keepalive", a, blocked)
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
	r.carry(eachInRecord(append(quick[:2:2], wgMessage{25 * s, true, wgKeepalive}, wgMessage{50 * s, true, wgKeepalive}), withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != 50*s || a.Reason != "WireGuard keepalives: 1 idle records of 51 bytes" {
		t.Errorf("keepalives 1: first blocked %+v (blocked %v), want a drop for the first keepalive at the next", a, blocked)
	}
	// A record answered within the window, one HTTP/2 PING, is no
	// keepalive, even as the last record before the answer.
	r = newWGRun(t, `{"keepalives": 1}`, 1400)
	r.carry(eachInRecord(append(quick[:2:2], wgMessage{25 * s, true, wgKeepalive}, wgMessage{25*s + 1500*time.Millisecond, false, wgKeepalive}), withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("keepalives 1, a PING answered in 1.5 s: blocked at %s: %+v", a.at, a)
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

// steadyStream is two-way traffic at rate records a second each way for
// d: each client record answered 20 ms later (or half the interval, if
// shorter), sizes from size.
func steadyStream(rate int, d time.Duration, size func() (client, server int)) []wireRecord {
	every := time.Second / time.Duration(rate)
	answer := min(20*time.Millisecond, every/2)
	var out []wireRecord
	for at := time.Duration(0); at < d; at += every {
		c, s := size()
		out = append(out, wireRecord{at, true, c}, wireRecord{at + answer, false, s})
	}
	return out
}

// TestWGRhythmSteadyStreams: a steady two-way stream of records in the
// handshake band never stands out, whatever its rate, so it is never taken
// for a rekey: equal sizes, random sizes, and request/reply probes every 2 s
// under 256-byte bucket padding, each for 6 minutes.
func TestWGRhythmSteadyStreams(t *testing.T) {
	s := time.Second
	for _, rate := range []int{1, 10, 50} {
		equal := func() (int, int) { return 273, 273 }
		cases := map[string][]wireRecord{fmt.Sprintf("equal sizes, %d/s", rate): steadyStream(rate, 360*s, equal)}
		for seed := range uint64(5) {
			rng := rand.New(rand.NewPCG(seed, 188))
			band := func() int { return wgBandMin + rng.IntN(wgBandMax-wgBandMin+1) }
			cases[fmt.Sprintf("random sizes, %d/s, seed %d", rate, seed)] = steadyStream(rate, 360*s, func() (int, int) { return band(), band() })
		}
		for name, recs := range cases {
			r := newWGRun(t, `{}`, 1400)
			r.carry(recs)
			if a, blocked := r.firstBlocked(); blocked {
				t.Errorf("%s: blocked at %s: %+v", name, a.at, a)
			}
		}
	}
	var probes []wireRecord
	for at := time.Duration(0); at < 360*s; at += 2 * s {
		probes = append(probes, wireRecord{at, true, 273}, wireRecord{at + 30*time.Millisecond, false, 273})
	}
	r := newWGRun(t, `{}`, 1400)
	r.carry(probes)
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("path probes every 2 s, padded to 256: blocked at %s: %+v", a.at, a)
	}
}

// TestWGRhythmCrossedKeepalives pins a known blind spot (lab/censor's
// package doc): when both peers send persistent keepalives in step, each
// answers the other within the window, so the keepalive signal never
// fires and the rekey is the only one.
func TestWGRhythmCrossedKeepalives(t *testing.T) {
	s := time.Second
	msgs := wgTimeline(false)
	for at := 25 * s; at < 260*s; at += 25 * s {
		msgs = append(msgs, wgMessage{at, true, wgKeepalive}, wgMessage{at + 20*time.Millisecond, false, wgKeepalive})
	}
	slices.SortStableFunc(msgs, func(a, b wgMessage) int { return int(a.at - b.at) })
	twoRekeys := slices.DeleteFunc(slices.Clone(msgs), func(m wgMessage) bool { return m.at >= 242*s })
	r := newWGRun(t, `{}`, 1400)
	r.carry(eachInRecord(twoRekeys, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); blocked {
		t.Errorf("crossed keepalives, two rekeys: blocked at %s: %+v; if the module now sees this, update the package doc", a.at, a)
	}
	r = newWGRun(t, `{}`, 1400)
	r.carry(eachInRecord(msgs, withOverhead(wgTLSOverhead)))
	if a, blocked := r.firstBlocked(); !blocked || a.at != wgRekeyAt || !strings.Contains(a.Reason, "rekey") {
		t.Errorf("crossed keepalives, three rekeys: first blocked %+v (blocked %v), want a drop for the rekey at %s", a, blocked, wgRekeyAt)
	}
}

// randomInBand is 6 minutes of 50 records a second each way of random
// sizes in the handshake band: nearly every pair of sizes exchanged.
func randomInBand() []wireRecord {
	rng := rand.New(rand.NewPCG(7, 188))
	band := func() int { return wgBandMin + rng.IntN(wgBandMax-wgBandMin+1) }
	return steadyStream(50, 360*time.Second, func() (int, int) { return band(), band() })
}

// TestWGRhythmPruneBounded: however many exchanges a connection carries,
// it drops the stale ones at most once a rekey window, so the work per
// record stays bounded by the band, never by the exchanges kept.
func TestWGRhythmPruneBounded(t *testing.T) {
	r := newWGRun(t, `{}`, 1400)
	r.carry(randomInBand())
	m := r.eng.passives[0].(*wgRhythm)
	if len(m.conns) != 1 {
		t.Fatalf("%d connections, want 1", len(m.conns))
	}
	for _, c := range m.conns {
		// 360 s with a window of 210 s: at the first exchange and once after.
		if c.prunes > 2 || len(c.exchanges) < 10_000 {
			t.Errorf("%d walks over up to %d exchanges, want at most 2 walks over more than 10000", c.prunes, len(c.exchanges))
		}
	}
}

func BenchmarkWGRhythmRandomInBand(b *testing.B) {
	recs := randomInBand()
	for b.Loop() {
		b.StopTimer()
		r := newWGRun(b, `{}`, 1400)
		b.StartTimer()
		r.carry(recs)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(recs)), "ns/record")
}
