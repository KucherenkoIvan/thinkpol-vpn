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
// interval wg(8) suggests. Every threshold below derives from them.
const (
	wgRekeyAfterTime      = 120 * time.Second
	wgRejectAfterTime     = 180 * time.Second
	wgRekeyTimeout        = 5 * time.Second
	wgKeepaliveTimeout    = 10 * time.Second
	wgPersistentKeepalive = 25 * time.Second
)

const (
	// wgPairWindow is how soon after one record the record the other way
	// must end to answer it: a round trip and the peer's work, well within
	// REKEY_TIMEOUT, after which WireGuard stops waiting for an answer to
	// its initiation and sends another.
	wgPairWindow = 2 * time.Second
	// wgQuiet is how long the connection must have carried no record, either
	// way, before a record counts as sent while idle: REKEY_TIMEOUT, under
	// KEEPALIVE_TIMEOUT (a passive keepalive comes that long after the last
	// packet received) and under any persistent keepalive interval.
	wgQuiet = wgRekeyTimeout
	// wgSteadyJitter is how far apart two intervals of an idle run may be
	// and still be one steady interval: WireGuard's keepalive timers have
	// no jitter (only its handshake retries do, under a third of a second).
	wgSteadyJitter = time.Second
	// wgRekeys is how many times an exchange must recur, each a rekey
	// period after the one before, to be WireGuard's rekey.
	wgRekeys = 3
	// wgRekeySlack widens the rekey window past REJECT_AFTER_TIME (for the
	// default period; scaled with a shorter one): WireGuard rekeys on the
	// first packet after its deadline, so the gap grows by up to a
	// persistent keepalive interval, and by a retried initiation's
	// REKEY_TIMEOUT.
	wgRekeySlack = wgPersistentKeepalive + wgRekeyTimeout
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
// from then on, both ways, on either signal:
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
//     (3) of them once the connection has carried an exchange, two more
//     without. A record counts once its wgPairWindow has passed, judged on
//     the connection's next packet either way.
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
	// trace, when set, gets a line for every record the module judges.
	trace io.Writer
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
	flagged string
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

// WGTraceLine is one line of wireguard-rhythm's trace: a record the module
// judged, on the flow of its direction, and what it made of it.
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
		m.settle(c, f.Last)
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
	c := &wgConn{exchanges: map[[2]int]*wgExchange{}}
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

// settle counts the pending idle record into the idle run once its answer
// window has passed by now, and flags the connection when the run shows
// the rhythm.
func (m *wgRhythm) settle(c *wgConn, now time.Time) {
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
	window := m.rekey*time.Duration(wgRejectAfterTime/time.Second)/time.Duration(wgRekeyAfterTime/time.Second) + wgRekeySlack
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
