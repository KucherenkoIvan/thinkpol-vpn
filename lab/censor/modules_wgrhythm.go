package censor

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

func init() {
	RegisterPassive("wireguard-rhythm", newWGRhythm)
}

// WireGuard's handshake message sizes (the WireGuard paper, section 5.4):
// an initiation and its response.
const (
	wgInitiation = 148
	wgResponse   = 92
)

const (
	// wgMaxOverhead bounds what a transport adds to a handshake message in
	// its record, padding included: TLS 1.3's tag and content type, framing
	// of its own, and padding up to a 256-byte bucket.
	wgMaxOverhead = 256
	// wgBandMin and wgBandMax are the handshake size band: a record either
	// handshake message could be, whatever the overhead of its direction.
	wgBandMin = wgResponse
	wgBandMax = wgInitiation + wgMaxOverhead
	// wgPairWindow is how soon after one record the record the other way
	// must end to answer it: a round trip and the peer's work.
	wgPairWindow = 2 * time.Second
	// wgQuiet is how long the connection must have carried no record, either
	// way, before a record counts as sent while idle. WireGuard's keepalives
	// come 10 s (passive) or the persistent interval after the last packet.
	wgQuiet = 5 * time.Second
	// wgSteadyJitter is how far apart two intervals of an idle run may be
	// and still be one steady interval: timers, not people, send these.
	wgSteadyJitter = time.Second
	// wgRekeys is how many times an exchange must recur, each a rekey
	// period after the one before, to be WireGuard's rekey.
	wgRekeys = 3
	// wgRekeySlack widens the rekey window past half a period again:
	// WireGuard rekeys on the first packet after its deadline, so the gap
	// grows by up to a persistent keepalive interval (25 s) and more.
	wgRekeySlack = 30 * time.Second
)

// wgRhythm flags a TLS connection that carries WireGuard with its rhythm
// showing (docs/design/milestones.md, M2): the handshake WireGuard runs
// every 2 minutes, and its keepalives. It reads recurrence, not
// WireGuard's exact sizes, so per-direction overhead and padding to small
// buckets don't hide it. It frames each direction's TLS records from the
// stream and looks at application-data records only: their sizes, their
// direction and when they ended. The connection shows the rhythm, and is
// decided with the module's verdict from then on, both ways, on either
// signal:
//
//   - rekey: an exchange (a record in the handshake size band one way and
//     one in the band the other way within wgPairWindow) that stands out,
//     each of its two sizes new to its direction over the rekey period
//     before it, or its first record sent after wgQuiet with no band
//     record either way, and
//     recurs standing out a rekey period after the latest time it did, up
//     to half as much again plus wgRekeySlack past it (WireGuard rekeys on
//     the first packet after 2 minutes when it sends, after 165 s when it
//     only receives), and again a period after that: wgRekeys in all.
//   - keepalive: an idle run, records of one size each sent after wgQuiet
//     with no record either way, none answered by a record the other way
//     within wgPairWindow, at one steady interval: at least `keepalives`
//     (3) of them once the connection has carried an exchange in the band,
//     two more without. A record counts once its wgPairWindow has passed,
//     judged on the connection's next packet either way.
//
// Flow shape beyond that (size distributions, bursts) is not its business
// (owner, 2026-11-07). A stream it can't frame as TLS from its first byte
// is never judged: not TLS, joined midstream, or with bytes the module
// wasn't shown (a module before it dropped their packet). It tags such a
// stream once, so a connection that passes for that reason shows in the
// verdict log.
type wgRhythm struct {
	verdict    Verdict
	rekey      time.Duration
	keepalives int
	conns      map[FlowKey]*wgConn
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
	// bandLast is when the latest band record either way ended.
	bandLast time.Time
	// exchanged is set once any exchange in the band has occurred.
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
	// band holds the latest record of each size in the handshake band,
	// for wgPairWindow: by age, not count, so a burst of data around a
	// handshake never pushes it out.
	band map[int]wgBandRecord
	// seen holds when the latest record of each size in the band ended,
	// for good: at most one entry a size.
	seen map[int]time.Time
}

type wgBandRecord struct {
	end time.Time
	// afterQuiet is set when no band record either way came within wgQuiet
	// before it; fresh when none of its size came its way within the rekey
	// period before it.
	afterQuiet, fresh bool
}

type wgRecord struct {
	dir  int
	size int
	end  time.Time
}

// wgExchange is one exchange's history: when its answer last ended, and
// the latest time it stood out, with how many times in a row it had then
// stood out a rekey period after the time before, and that gap.
type wgExchange struct {
	seen  time.Time
	stood time.Time
	chain int
	gap   time.Duration
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
//	{"verdict": "drop", "rekey": "120s", "keepalives": 3}
//
// verdict is drop (default) or reset; rekey is WireGuard's rekey period
// (tests shorten it to see three rekeys quickly); keepalives is how many
// records an idle run needs to show the rhythm once the connection has
// carried an exchange in the handshake band (without one, two more).
func newWGRhythm(settings json.RawMessage) (Passive, error) {
	var s struct {
		Verdict    string `json:"verdict"`
		Rekey      string `json:"rekey"`
		Keepalives *int   `json:"keepalives"`
	}
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &s); err != nil {
			return nil, err
		}
	}
	m := &wgRhythm{rekey: 120 * time.Second, keepalives: 3, conns: map[FlowKey]*wgConn{}}
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
	return m, nil
}

func (m *wgRhythm) Name() string { return "wireguard-rhythm" }

func (m *wgRhythm) Inspect(p *Packet, f *Flow) Decision {
	// The stream kept a bad-checksum packet out and left Fresh as the
	// packet before it had it.
	if f.Stream == nil || p.BadChecksum {
		return Decision{Verdict: Accept}
	}
	c, dir := m.conn(f)
	if c.flagged == "" {
		m.settle(c, f.Last)
	}
	if c.flagged == "" && m.read(c, dir, f) {
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
		c.dirs[i].band, c.dirs[i].seen = map[int]wgBandRecord{}, map[int]time.Time{}
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
				m.record(c, dir, d, f.Last)
				continue
			}
		}
		n := min(d.body, len(b))
		d.body, b = d.body-n, b[n:]
		if d.body == 0 {
			m.record(c, dir, d, f.Last)
		}
	}
	return false
}

// record judges one whole record of direction dir that ended at end.
func (m *wgRhythm) record(c *wgConn, dir int, d *wgDirection, end time.Time) {
	if !d.appData || c.flagged != "" {
		return
	}
	r := wgRecord{dir, d.size, end}
	if p := c.pending; p != nil && r.dir != p.dir && end.Sub(p.end) <= wgPairWindow {
		c.pending = nil // answered: not a keepalive
	}
	if r.size >= wgBandMin && r.size <= wgBandMax {
		seen, ok := d.seen[r.size]
		fresh := !ok || end.Sub(seen) >= m.rekey
		d.seen[r.size] = end
		for size, b := range c.dirs[1-dir].band {
			if end.Sub(b.end) > wgPairWindow {
				delete(c.dirs[1-dir].band, size)
				continue
			}
			c.exchanged = true
			if m.exchange(c, [2]int{size, r.size}, b.afterQuiet || b.fresh && fresh, end) {
				return
			}
		}
		quiet := c.bandLast.IsZero() || end.Sub(c.bandLast) >= wgQuiet
		d.band[r.size] = wgBandRecord{end, quiet, fresh}
		c.bandLast = end
	}
	idle := !c.last.IsZero() && end.Sub(c.last) >= wgQuiet
	c.last = end
	if idle {
		c.pending = &r
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
// It reports whether it flagged.
func (m *wgRhythm) exchange(c *wgConn, sizes [2]int, stands bool, end time.Time) bool {
	window := m.rekey*3/2 + wgRekeySlack
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
		// More answers to one record are one occurrence.
		e.seen = end
		return false
	}
	e.seen = end
	if !stands {
		return false
	}
	gap := end.Sub(e.stood)
	if e.chain > 0 && gap >= m.rekey && gap <= window {
		e.chain++
	} else {
		e.chain, gap = 1, 0
	}
	e.stood, e.gap = end, gap
	if e.chain < wgRekeys {
		return false
	}
	c.flagged = fmt.Sprintf("WireGuard rekey: records of %d and %d bytes exchanged %d times, the last %s apart",
		sizes[0], sizes[1], e.chain, e.gap.Round(time.Second))
	return true
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
