package censor

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"
)

func init() {
	RegisterPassive("wireguard-rhythm", newWGRhythm)
}

// WireGuard's timers, as wireguard-go defines them (device/constants.go,
// after the protocol paper's REKEY_AFTER_TIME, REJECT_AFTER_TIME,
// REKEY_TIMEOUT and KEEPALIVE_TIMEOUT), and the persistent keepalive
// interval wg(8) suggests, which thinkpol doesn't set
// (internal/dataplane/wg). The thresholds below derive from them, but for
// wgPairWindow, wgSteadyJitter, wgRekeys, wgCountSettle, wgCountHold,
// wgBurstGap, wgBurstMax and the keepalive count: those are the module's
// choices, no WireGuard timer.
const (
	wgRekeyAfterTime      = 120 * time.Second
	wgRejectAfterTime     = 180 * time.Second
	wgRekeyTimeout        = 5 * time.Second
	wgKeepaliveTimeout    = 10 * time.Second
	wgPersistentKeepalive = 25 * time.Second
)

const (
	// wgPairWindow is how soon after one record the record the other way
	// must end to answer it: a choice, a round trip and the peer's work
	// with room to spare, kept under REKEY_TIMEOUT, after which WireGuard
	// stops waiting for an answer to its initiation and sends another.
	wgPairWindow = 2 * time.Second
	// wgQuiet is how long the connection must have carried no record, either
	// way, before a record counts as sent while idle: REKEY_TIMEOUT, under
	// KEEPALIVE_TIMEOUT (a passive keepalive comes that long after the last
	// packet received) and under any persistent keepalive interval.
	wgQuiet = wgRekeyTimeout
	// wgSteadyJitter is how far apart two intervals of an idle run may be
	// and still be one steady interval: a choice. WireGuard's keepalive
	// timers have no jitter (only its handshake retries do, under a third
	// of a second); the second is room for scheduling and the transport.
	wgSteadyJitter = time.Second
	// wgRekeys is how many times an exchange must recur, each a rekey
	// period after the one before, to be WireGuard's rekey: a choice,
	// against chance recurrences (see the measured false positives in
	// doc.go), which costs up to 7 minutes of a connection.
	wgRekeys = 3
	// wgRekeySlack widens the rekey window past REJECT_AFTER_TIME (for the
	// default period; scaled with a shorter one): WireGuard rekeys on the
	// first packet after its deadline, so with wg(8)'s persistent
	// keepalive the gap grows by up to that interval, and by a retried
	// initiation's REKEY_TIMEOUT. thinkpol runs no persistent keepalive:
	// its next packet past the deadline comes only with traffic, so a
	// tunnel that carries nothing from REKEY_AFTER_TIME until the window
	// has passed (about 90 s at the default period) rekeys too late, its
	// chain starts over, and a tunnel used in bursts that far apart is
	// missed by the rekey signal.
	wgRekeySlack = wgPersistentKeepalive + wgRekeyTimeout
	// wgCountSettle is how long the connection must carry no record,
	// either way, for its record count each way to be read as a level: a
	// choice, longer than a round trip and a WireGuard handshake in the
	// lab, shorter than the gaps of a ping every 2 s or of thinkpol's path
	// probes. Where a round trip takes longer, a request in flight is
	// read off the level until its answer comes (wgCountHold).
	wgCountSettle = 300 * time.Millisecond
	// wgCountHold is how long after the records that took the difference
	// to a value off the level it must read that value again to be a
	// step: a choice, the time an answer has. A request whose answer
	// comes later than wgCountSettle (a loaded path or censor) but within
	// wgPairWindow takes the count off its level, or to another value
	// off it, for no longer than that, and is no step.
	wgCountHold = wgPairWindow
	// wgBurstGap is how close a record must end to the one before, either
	// way, to be in its burst: a choice, a few ms, room for a handshake
	// where the censor sees it start to end within a few ms (the lab's
	// router; a censor beside the initiator sees the response and its
	// confirming keepalive back to back too).
	wgBurstGap = 10 * time.Millisecond
	// wgBurstMax is the most records one way a burst may hold to be a
	// handshake: a choice, room for the initiation, the confirming
	// keepalive and the packet that triggered the rekey, against the
	// response and that packet's answer. Bigger bursts are taken for
	// other traffic's (measured, doc.go).
	wgBurstMax = 3
)

// WGRhythmByCount and WGRhythmByBurst start the count and burst
// signals' block reasons, so a lab cell can tell which signal blocked.
const (
	WGRhythmByCount = "WireGuard rekey by record count"
	WGRhythmByBurst = "WireGuard rekey by burst"
)

// wgRhythm flags a connection that carries WireGuard with its rhythm
// showing (docs/design/milestones.md, M2): the handshake WireGuard runs
// every 2 minutes, and its keepalives. It reads timing and recurrence, not
// WireGuard's sizes: a record of any size takes part, so per-direction
// overhead and padding to any bucket don't hide it. Over TCP it frames
// each direction's TLS records from the stream and looks at
// application-data records only; over UDP each datagram is a record. Of a
// record it reads its size, its direction and when it ended. The
// connection shows the rhythm, and is decided with the module's verdict
// from then on, both ways, on any of its signals:
//
//   - rekey: an exchange (a record one way and one the other way within
//     wgPairWindow) that stands out, each of its two sizes new to its
//     direction over the rekey period before it, or its first record sent
//     after wgQuiet with no record either way (a record takes on the
//     standing out of one of its size sent its way within wgPairWindow
//     before it, as an initiation padded to its trigger's size), and
//     stands out again a rekey period after the latest time it did, up to
//     REJECT_AFTER_TIME plus wgRekeySlack past it (WireGuard rekeys on the
//     first packet past REKEY_AFTER_TIME when it sends, past
//     REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT when it only
//     receives), and again a period after that: wgRekeys in all.
//   - keepalive: an idle run, records of one size each sent after wgQuiet
//     with no record either way, none answered by a record the other way
//     within wgPairWindow, at one steady interval: at least `keepalives`
//     (3 by default, a choice like wgRekeys) of them once the connection
//     has carried an exchange, two more without. A record counts once its
//     wgPairWindow has passed, judged on the connection's next packet
//     either way.
//   - count: each WireGuard handshake leaves the initiator one record
//     ahead (initiation and confirming keepalive against the response;
//     what triggered it is answered or not as any data), so with traffic
//     even both ways the difference of the record counts each way, read
//     whenever the connection carried no record for wgCountSettle, steps
//     by the same amount at each rekey and stays flat in between. A
//     difference read off the level is a step once the readings have
//     found it, unchanged, wgCountHold after the records that took it
//     there, so an answer that comes late is none. A step is timed as a span, from
//     the records that took the difference off the level to those that
//     took it to the value it stepped to, so it holds the handshake's
//     records however busy the connection was around them. It shows the
//     rhythm when the difference steps by one amount wgRekeys times in a
//     row, each step ending a rekey period or more after the one before
//     began and beginning within the rekey window of its end, with no
//     other change in between.
//   - burst: the same handshake seen whole, as a burst (records each
//     within wgBurstGap of the one before, either way) with one record
//     more one way than the other, at least one each way and at most
//     wgBurstMax, recurring
//     with the same counts wgRekeys times in a row, each a rekey period to
//     the rekey window after the one before; a burst of those counts
//     sooner than a rekey period starts the chain over.
//
// Flow shape beyond that (size distributions, bursts) is not its business
// (owner, 2026-11-07). A TCP stream it can't frame as TLS from its first
// byte is never judged: not TLS, joined midstream, or with bytes the
// module wasn't shown (a module before it dropped their packet). It tags
// such a stream once, so a connection that passes for that reason shows
// in the verdict log.
type wgRhythm struct {
	verdict    Verdict
	rekey      time.Duration
	keepalives int
	conns      map[FlowKey]*wgConn
	// trace, when set, gets a line for every record the module judges:
	// a synchronous write in the packet path, a few hundred bytes a
	// record, fine at the lab's rates.
	trace io.WriteCloser
}

// wgConn is one connection's state, both directions, keyed by the flow
// key of the direction the module saw first.
type wgConn struct {
	// flows are the two directions' flows the state was built from; a
	// flow the engine started over is a new connection.
	flows [2]*Flow
	dirs  [2]wgDirection
	// last is when the latest application-data record either way ended.
	last time.Time
	// exchanges holds each exchange seen within the rekey window, by the
	// sizes of its two records; pruned is when stale ones were last
	// dropped, at most once a window so a record's work stays bounded;
	// prunes counts the walks.
	exchanges map[[2]int]*wgExchange
	pruned    time.Time
	prunes    int
	// exchanged is set once any exchange has occurred.
	exchanged bool
	// pending is the latest idle record while it may still be answered.
	pending *wgRecord
	run     wgIdleRun
	// count is the count signal's state, burst the latest burst while it
	// may still grow, bursts the burst signal's chains by the burst's
	// records each way, pruned like exchanges.
	count        wgCount
	burst        wgRecordBurst
	bursts       map[[2]int]*wgChain
	burstsPruned time.Time
	flagged      string
}

// wgCount is the count signal's state: records each way, the difference
// last held as a level, when the records since the latest reading began,
// the records the latest reading on the level read, the move off the
// level not yet a step, and the chain of the level's steps.
type wgCount struct {
	n       [2]int
	level   int
	leveled bool // a level has been read
	settled bool // the difference has been read since the latest record
	since   time.Time
	// onLevel spans the records the latest reading that found the level
	// read: an answer in flight then can have hidden a move from it.
	onLevel wgSpan
	move    wgMove
	chain   wgCountChain
}

// wgSpan is a run of records: when its first and its last ended.
type wgSpan struct{ start, end time.Time }

// wgMove is a difference read off the level and not yet a step: when the
// records that took it off began (zero while it reads the level), and
// the latest value it was read at, with when the records that took it to
// that value ended.
type wgMove struct {
	start  time.Time
	latest wgMoveValue
}

type wgMoveValue struct {
	d   int
	end time.Time
}

// wgCountChain is a run of the count's steps of one amount, each timed as
// a span: the latest one, how many, and how far apart the latest two
// began.
type wgCountChain struct {
	span  wgSpan
	n     int
	gap   time.Duration
	delta int
}

// next counts a step timed by span into the chain: one that ends least
// or more after the latest began, and begins no later than window after
// it ended, continues it; any other starts it over. The handshake lies in
// both spans, so rekeys least to window apart always continue it; steps
// whose spans are L long continue it when they begin least - L to
// window + L apart, a wider range for false positives (lab/censor/doc.go).
func (ch *wgCountChain) next(span wgSpan, least, window time.Duration) {
	if ch.n > 0 && span.end.Sub(ch.span.start) >= least && span.start.Sub(ch.span.end) <= window {
		ch.n, ch.gap = ch.n+1, span.start.Sub(ch.span.start)
	} else {
		ch.n, ch.gap = 1, 0
	}
	ch.span = span
}

// wgRecordBurst is a burst of records each within wgBurstGap of the one
// before: when it began and its records each way.
type wgRecordBurst struct {
	start time.Time
	n     [2]int
}

// wgChain is a run of occurrences each a rekey period to the rekey
// window after the one before: the latest one, how many, and the latest
// gap.
type wgChain struct {
	at  time.Time
	n   int
	gap time.Duration
}

// next counts an occurrence at at into the chain: one least to window
// after the latest continues it, any other starts it over.
func (ch *wgChain) next(at time.Time, least, window time.Duration) {
	gap := at.Sub(ch.at)
	if ch.n > 0 && gap >= least && gap <= window {
		ch.n, ch.gap = ch.n+1, gap
	} else {
		ch.n, ch.gap = 1, 0
	}
	ch.at = at
}

// wgDirection frames one direction's TLS records.
type wgDirection struct {
	header  []byte // a record header split over packets, so far
	body    int    // bytes of the current record's body still to come
	size    int    // the current record's length
	appData bool   // the current record is application data
	// unframed is set for good once the direction's records can't be
	// told apart: bytes that aren't a TLS record header where one is due,
	// a stream joined midstream, or stream bytes the module never saw.
	unframed bool
	consumed uint64 // stream bytes framed so far
	// recent holds the latest record of each size, for wgPairWindow: by
	// age, not count, so a burst of data around a handshake never pushes
	// it out.
	recent map[int]wgRecentRecord
	// seen holds when the latest record of each size ended, for good: at
	// most one entry a size.
	seen map[int]time.Time
}

type wgRecentRecord struct {
	end time.Time
	// afterQuiet is set when no record either way came within wgQuiet
	// before it; fresh when none of its size came its way within the rekey
	// period before it.
	afterQuiet, fresh bool
}

type wgRecord struct {
	dir  int
	size int
	end  time.Time
}

// wgExchange is one exchange's history: when its answer last ended,
// whether that occurrence stood out, and the latest time it stood out,
// with how many times in a row it had then stood out a rekey period after
// the time before, and that gap.
type wgExchange struct {
	seen     time.Time
	standing bool
	stood    time.Time
	chain    int
	gap      time.Duration
}

// wgIdleRun is the connection's latest idle run: n unanswered idle records of
// size bytes, the latest two ending at prev and last.
type wgIdleRun struct {
	size       int
	n          int
	prev, last time.Time
}

// newWGRhythm builds the module from its settings:
//
//	{"verdict": "drop", "rekey": "120s", "keepalives": 3,
//	 "trace": "/run/censor/rhythm.jsonl"}
//
// verdict is drop (default) or reset; rekey is WireGuard's rekey period,
// REKEY_AFTER_TIME (tests shorten it to see three rekeys quickly);
// keepalives is how many records an idle run needs to show the rhythm
// once the connection has carried an exchange (without one, two more);
// trace, if set, is a file the module appends a JSON line to for every
// record it judges ([WGTraceLine]), so a lab test can say what a
// connection showed, flagged or not.
func newWGRhythm(settings json.RawMessage) (Passive, error) {
	var s struct {
		Verdict    string `json:"verdict"`
		Rekey      string `json:"rekey"`
		Keepalives *int   `json:"keepalives"`
		Trace      string `json:"trace"`
	}
	if err := unmarshalSettings(settings, &s); err != nil {
		return nil, err
	}
	m := &wgRhythm{rekey: wgRekeyAfterTime, keepalives: 3, conns: map[FlowKey]*wgConn{}}
	switch s.Verdict {
	case "", "drop":
		m.verdict = Drop
	case "reset":
		m.verdict = Reset
	default:
		return nil, fmt.Errorf("verdict %q: want drop or reset", s.Verdict)
	}
	if s.Rekey != "" {
		d, err := time.ParseDuration(s.Rekey)
		if err != nil || d <= wgPairWindow {
			return nil, fmt.Errorf("rekey %q: want a duration longer than %s", s.Rekey, wgPairWindow)
		}
		m.rekey = d
	}
	if s.Keepalives != nil {
		if *s.Keepalives < 1 {
			return nil, fmt.Errorf("keepalives %d: want 1 or more", *s.Keepalives)
		}
		m.keepalives = *s.Keepalives
	}
	if s.Trace != "" {
		// censord runs until the lab stops it: the file is closed with
		// the process.
		f, err := os.OpenFile(s.Trace, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("trace: %w", err)
		}
		m.trace = f
	}
	return m, nil
}

// closeTrace closes the trace file, if any. censord never calls it (the
// file closes with the process); tests do.
func (m *wgRhythm) closeTrace() error {
	if m.trace == nil {
		return nil
	}
	return m.trace.Close()
}

// WGTraceLine is one line of wireguard-rhythm's trace: a record the module
// judged, on the flow of its direction, and what it made of it. A line of
// size 0 is no record: the flag the count or burst signal raised in the
// quiet after a record, at the packet that ended the quiet.
type WGTraceLine struct {
	Flow string    `json:"flow"`
	End  time.Time `json:"end"`
	Size int       `json:"size"`
	// AfterQuiet: no record either way within wgQuiet before it; Fresh: no
	// record of its size its way within the rekey period before it.
	AfterQuiet bool `json:"afterQuiet,omitempty"`
	Fresh      bool `json:"fresh,omitempty"`
	// StoodOut is how many times in a row, a rekey period apart, the
	// exchange the record answered had then stood out (0: it answered
	// none that stood out).
	StoodOut int `json:"stoodOut,omitempty"`
	// Flagged is the connection's flag, once this record showed the
	// rhythm.
	Flagged string `json:"flagged,omitempty"`
}

func (m *wgRhythm) Name() string { return "wireguard-rhythm" }

func (m *wgRhythm) Inspect(p *Packet, f *Flow) Decision {
	// The stream kept a bad-checksum packet out and left Fresh as the
	// packet before it had it; a receiver discards such a datagram.
	if p.BadChecksum || p.Proto != ProtoTCP && p.Proto != ProtoUDP || p.Proto == ProtoTCP && f.Stream == nil {
		return Decision{Verdict: Accept}
	}
	c, dir := m.conn(f)
	if c.flagged == "" {
		m.settle(c, f, f.Last)
	}
	switch {
	case c.flagged != "":
	case p.Proto == ProtoUDP:
		m.record(c, dir, f, len(p.Payload), f.Last)
	case m.read(c, dir, f):
		return Decision{Verdict: Accept, Tag: "wireguard-rhythm: stream not framed"}
	}
	if c.flagged == "" {
		return Decision{Verdict: Accept}
	}
	return Decision{Verdict: m.verdict, Flow: true, Reason: c.flagged}
}

// conn finds a flow's connection state and which direction of it the
// flow is: 0 the one the module saw first, 1 its reverse. Flows the
// engine started over are a new connection, with state of its own.
func (m *wgRhythm) conn(f *Flow) (*wgConn, int) {
	if c, ok := m.conns[f.Key]; ok && c.flows[0] == f {
		return c, 0
	}
	if c, ok := m.conns[f.Key.Reverse()]; ok && c.flows[1] == f {
		return c, 1
	}
	if r := f.Reverse(); r != nil {
		if c, ok := m.conns[r.Key]; ok && c.flows[0] == r && c.flows[1] == nil {
			c.flows[1] = f
			return c, 1
		}
	}
	// Whatever state either key still has is of an older connection.
	delete(m.conns, f.Key.Reverse())
	c := &wgConn{exchanges: map[[2]int]*wgExchange{}, bursts: map[[2]int]*wgChain{}}
	for i := range c.dirs {
		c.dirs[i].recent, c.dirs[i].seen = map[int]wgRecentRecord{}, map[int]time.Time{}
	}
	c.flows[0] = f
	m.conns[f.Key] = c
	return c, 0
}

// read frames the records the flow's latest packet completed, and judges
// each. It reports whether the direction just became unframed.
func (m *wgRhythm) read(c *wgConn, dir int, f *Flow) bool {
	d := &c.dirs[dir]
	if d.unframed {
		return false
	}
	if f.Stream.Midstream() || f.Stream.Delivered() != d.consumed+uint64(len(f.Stream.Fresh())) {
		d.unframed = true
		return true
	}
	b := f.Stream.Fresh()
	d.consumed += uint64(len(b))
	for len(b) > 0 {
		if d.body == 0 {
			n := min(5-len(d.header), len(b))
			d.header, b = append(d.header, b[:n]...), b[n:]
			if len(d.header) < 5 {
				return false
			}
			h := d.header
			d.header = d.header[:0]
			if h[0] < 0x14 || h[0] > 0x17 || h[1] != 3 || h[2] > 4 {
				d.unframed = true
				return true
			}
			d.size, d.appData = int(binary.BigEndian.Uint16(h[3:])), h[0] == 0x17
			d.body = d.size
			if d.body == 0 {
				m.appData(c, dir, f)
				continue
			}
		}
		n := min(d.body, len(b))
		d.body, b = d.body-n, b[n:]
		if d.body == 0 {
			m.appData(c, dir, f)
		}
	}
	return false
}

// appData judges the record of direction dir the flow's latest packet
// completed, if it is application data.
func (m *wgRhythm) appData(c *wgConn, dir int, f *Flow) {
	if d := &c.dirs[dir]; d.appData {
		m.record(c, dir, f, d.size, f.Last)
	}
}

// record judges one whole record of size bytes, of direction dir (the
// flow f), that ended at end.
func (m *wgRhythm) record(c *wgConn, dir int, f *Flow, size int, end time.Time) {
	if c.flagged != "" {
		return
	}
	if c.last.IsZero() || end.Sub(c.last) >= wgCountSettle {
		c.count.since = end
	}
	c.count.n[dir]++
	c.count.settled = false
	if c.burst.n == [2]int{} {
		c.burst.start = end
	}
	c.burst.n[dir]++
	d := &c.dirs[dir]
	r := wgRecord{dir, size, end}
	if p := c.pending; p != nil && r.dir != p.dir && end.Sub(p.end) <= wgPairWindow {
		c.pending = nil // answered: not a keepalive
	}
	seen, ok := d.seen[size]
	fresh := !ok || end.Sub(seen) >= m.rekey
	d.seen[size] = end
	quiet := c.last.IsZero() || end.Sub(c.last) >= wgQuiet
	stood := 0
	// In order of size, so which of two exchanges flags first doesn't
	// depend on map order.
	other := c.dirs[1-dir].recent
	for _, s := range slices.Sorted(maps.Keys(other)) {
		b := other[s]
		if end.Sub(b.end) > wgPairWindow {
			delete(other, s)
			continue
		}
		c.exchanged = true
		stood = max(stood, m.exchange(c, [2]int{s, size}, b.afterQuiet || b.fresh && fresh, end))
		if c.flagged != "" {
			break
		}
	}
	m.traced(f, size, end, quiet, fresh, stood, c.flagged)
	if c.flagged != "" {
		return
	}
	// A record of this size just before (a trigger padded to its
	// initiation's size) leaves this one neither fresh nor after quiet;
	// the two are one record to answer, so it keeps that one's.
	if b, ok := d.recent[size]; ok && end.Sub(b.end) <= wgPairWindow {
		quiet, fresh = quiet || b.afterQuiet, fresh || b.fresh
	}
	d.recent[size] = wgRecentRecord{end, quiet, fresh}
	idle := !c.last.IsZero() && end.Sub(c.last) >= wgQuiet
	c.last = end
	if idle {
		c.pending = &r
	}
}

// traced writes the record's trace line, if the module traces.
func (m *wgRhythm) traced(f *Flow, size int, end time.Time, quiet, fresh bool, stood int, flagged string) {
	if m.trace == nil {
		return
	}
	b, err := json.Marshal(WGTraceLine{Flow: f.Key.String(), End: end, Size: size, AfterQuiet: quiet, Fresh: fresh, StoodOut: stood, Flagged: flagged})
	if err == nil {
		_, _ = m.trace.Write(append(b, '\n'))
	}
}

// settle closes the burst and reads the count once the connection has
// been quiet long enough for each by now, counts the pending idle record
// into the idle run once its answer window has passed, and flags the
// connection when any of them shows the rhythm.
func (m *wgRhythm) settle(c *wgConn, f *Flow, now time.Time) {
	if !c.last.IsZero() && now.Sub(c.last) > wgBurstGap && c.burst.n != [2]int{} {
		m.closeBurst(c)
	}
	// A move not yet a step is read again, though no record came since,
	// so its hold ends on the next packet rather than the next record's
	// reading, which would count that record into it.
	if !c.last.IsZero() && now.Sub(c.last) >= wgCountSettle && (!c.count.settled || !c.count.move.start.IsZero()) {
		m.readCount(c, now)
	}
	if c.flagged != "" {
		// The flag's own line: no record, the packet it came on.
		m.traced(f, 0, now, false, false, 0, c.flagged)
		return
	}
	p := c.pending
	if p == nil || now.Sub(p.end) <= wgPairWindow {
		return
	}
	c.pending = nil
	c.run.add(*p)
	need := m.keepalives
	if !c.exchanged {
		need += 2
	}
	if c.run.n >= need {
		c.flagged = fmt.Sprintf("WireGuard keepalives: %d idle records of %d bytes", c.run.n, c.run.size)
		if c.run.n > 1 {
			c.flagged += fmt.Sprintf(", %s apart", c.run.last.Sub(c.run.prev).Round(time.Second))
		}
	}
}

// exchange notes an occurrence of the exchange of sizes, standing out or
// not, the answer ending at end, and flags the connection when it stands
// out the wgRekeys-th time in a row a rekey period after the time before.
// It returns how many times in a row the exchange has stood out, if this
// occurrence made it stand out, else 0.
func (m *wgRhythm) exchange(c *wgConn, sizes [2]int, stands bool, end time.Time) int {
	window := m.window()
	if end.Sub(c.pruned) >= window {
		for k, e := range c.exchanges {
			if end.Sub(e.seen) > window {
				delete(c.exchanges, k)
			}
		}
		c.pruned = end
		c.prunes++
	}
	e := c.exchanges[sizes]
	if e == nil {
		e = &wgExchange{}
		c.exchanges[sizes] = e
	} else if end.Sub(e.seen) <= wgPairWindow {
		// More answers to one record are one occurrence, which stands out
		// if any of them does.
		e.seen = end
		if !stands || e.standing {
			return 0
		}
	}
	e.seen, e.standing = end, stands
	if !stands {
		return 0
	}
	gap := end.Sub(e.stood)
	if e.chain > 0 && gap >= m.rekey && gap <= window {
		e.chain++
	} else {
		e.chain, gap = 1, 0
	}
	e.stood, e.gap = end, gap
	if e.chain >= wgRekeys {
		c.flagged = fmt.Sprintf("WireGuard rekey: records of %d and %d bytes exchanged %d times, the last %s apart",
			sizes[0], sizes[1], e.chain, e.gap.Round(time.Second))
	}
	return e.chain
}

// window is the latest a rekey comes after the one before:
// REJECT_AFTER_TIME, scaled with a shorter rekey period, and wgRekeySlack.
func (m *wgRhythm) window() time.Duration {
	return m.rekey*time.Duration(wgRejectAfterTime/time.Second)/time.Duration(wgRekeyAfterTime/time.Second) + wgRekeySlack
}

// readCount reads the difference of the record counts each way, the
// connection having carried no record for wgCountSettle, at now. A
// difference off the level is a move: a step once a reading finds the
// latest value the move was read at again, wgCountHold or more after the
// records that took it to that value ended. Any other value off the
// level is the move's latest (a request whose answer is still to come,
// on top of the move or not), even one the move was read at before: a
// late answer can take the count back to that value, and it would
// confirm a step the request's answer then undoes. One back on the level
// ends the move, no step. A step is timed as the span from the records
// that took the difference off the level (or those the reading on the
// level before read, when they ended within wgPairWindow before: an
// answer in flight then can have hidden the move) to the records that
// took it to the value it stepped to. It flags the connection when the level has
// stepped by one amount wgRekeys times in a row, a rekey period apart,
// with no other change.
func (m *wgRhythm) readCount(c *wgConn, now time.Time) {
	k := &c.count
	k.settled = true
	d := k.n[0] - k.n[1]
	read := wgSpan{k.since, c.last}
	switch {
	case !k.leveled:
		k.level, k.leveled, k.onLevel = d, true, read
		return
	case d == k.level:
		k.move, k.onLevel = wgMove{}, read
		return
	case k.move.start.IsZero():
		start := read.start
		if !k.onLevel.end.IsZero() && read.start.Sub(k.onLevel.end) <= wgPairWindow {
			start = k.onLevel.start
		}
		k.move = wgMove{start, wgMoveValue{d, read.end}}
	}
	mv := &k.move
	switch {
	case d != mv.latest.d:
		mv.latest = wgMoveValue{d, read.end}
		return
	case now.Sub(mv.latest.end) < wgCountHold:
		return
	}
	step, span := d-k.level, wgSpan{mv.start, mv.latest.end}
	k.level, k.move, k.onLevel = d, wgMove{}, read
	if step != k.chain.delta {
		k.chain = wgCountChain{delta: step}
	}
	k.chain.next(span, m.rekey, m.window())
	if k.chain.n >= wgRekeys {
		c.flagged = fmt.Sprintf(WGRhythmByCount+": the difference each way stepped %d times by %+d, the last %s apart, flat in between",
			k.chain.n, step, k.chain.gap.Round(time.Second))
	}
}

// closeBurst ends the latest burst and, if it has one record more one way
// than the other, records both ways and no more than wgBurstMax either
// way, chains it with the bursts of its
// counts before it, flagging the connection when they recur wgRekeys
// times in a row a rekey period apart.
func (m *wgRhythm) closeBurst(c *wgConn) {
	b := c.burst
	c.burst = wgRecordBurst{}
	lo, hi := min(b.n[0], b.n[1]), max(b.n[0], b.n[1])
	if lo < 1 || hi != lo+1 || hi > wgBurstMax {
		return
	}
	window := m.window()
	if b.start.Sub(c.burstsPruned) >= window {
		for k, ch := range c.bursts {
			if b.start.Sub(ch.at) > window {
				delete(c.bursts, k)
			}
		}
		c.burstsPruned = b.start
	}
	ch := c.bursts[b.n]
	if ch == nil {
		ch = &wgChain{}
		c.bursts[b.n] = ch
	}
	ch.next(b.start, m.rekey, window)
	if ch.n >= wgRekeys {
		c.flagged = fmt.Sprintf(WGRhythmByBurst+": %d records one way and %d the other within %s, %d times, the last %s apart",
			b.n[0], b.n[1], wgBurstGap, ch.n, ch.gap.Round(time.Second))
	}
}

// with is how long the run would be with r, an idle record, in it.
func (u *wgIdleRun) with(r wgRecord) int {
	if u.n == 0 || r.size != u.size {
		return 1
	}
	if u.n >= 2 && !steady(u.last.Sub(u.prev), r.end.Sub(u.last)) {
		return 1
	}
	return u.n + 1
}

// add puts an unanswered idle record into the run, or starts a run with
// it.
func (u *wgIdleRun) add(r wgRecord) {
	if n := u.with(r); n > 1 {
		u.n, u.prev, u.last = n, u.last, r.end
		return
	}
	*u = wgIdleRun{size: r.size, n: 1, last: r.end}
}

func steady(a, b time.Duration) bool {
	return a-b <= wgSteadyJitter && b-a <= wgSteadyJitter
}
