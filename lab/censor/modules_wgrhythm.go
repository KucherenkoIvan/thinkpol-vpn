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
	// wgRekeys is how many times an exchange must occur, each a rekey
	// period after the one before, to be WireGuard's rekey.
	wgRekeys = 3
	// wgExchangesKept bounds the distinct exchanges a connection keeps
	// before the stale ones are dropped.
	wgExchangesKept = 1024
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
//     one in the band the other way within wgPairWindow) whose two sizes
//     occur again as an exchange a rekey period later, from the period to
//     half as much again past it (WireGuard rekeys after 2 minutes when it
//     sends, and up to 45 s later when it only receives), and again a
//     period after that: wgRekeys occurrences in all.
//   - keepalive: an idle run, records of one size each sent after wgQuiet
//     with no record either way, none answered by a record the other way
//     within wgPairWindow, at one steady interval: at least `keepalives`
//     (3) of them once the connection has carried an exchange in the band,
//     two more without.
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
	// exchanges holds each exchange's occurrences within the last
	// rekey*3/2, by the sizes of its two records.
	exchanges map[[2]int][]wgOccurrence
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
	// band holds when the latest record of each size in the handshake
	// band ended, for wgPairWindow: by age, not count, so a burst of data
	// around a handshake never pushes it out.
	band map[int]time.Time
}

type wgRecord struct {
	dir  int
	size int
	end  time.Time
}

// wgOccurrence is one occurrence of an exchange: when its answer ended,
// how many occurrences a rekey period apart end with it, and the gap to
// the one before it in that chain.
type wgOccurrence struct {
	at    time.Time
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
	c := &wgConn{exchanges: map[[2]int][]wgOccurrence{}}
	c.dirs[0].band, c.dirs[1].band = map[int]time.Time{}, map[int]time.Time{}
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
	if p := c.pending; p != nil {
		switch {
		case r.dir != p.dir && end.Sub(p.end) <= wgPairWindow:
			c.pending = nil // answered: not a keepalive
		case end.Sub(p.end) > wgPairWindow:
			c.run.add(*p)
			c.pending = nil
		}
	}
	if r.size >= wgBandMin && r.size <= wgBandMax {
		for size, at := range c.dirs[1-dir].band {
			if end.Sub(at) > wgPairWindow {
				delete(c.dirs[1-dir].band, size)
				continue
			}
			c.exchanged = true
			m.exchange(c, [2]int{size, r.size}, end)
		}
		d.band[r.size] = end
	}
	idle := !c.last.IsZero() && end.Sub(c.last) >= wgQuiet
	c.last = end
	if c.flagged != "" || !idle {
		return
	}
	need := m.keepalives
	if !c.exchanged {
		need += 2
	}
	if n := c.run.with(r); n >= need {
		c.flagged = fmt.Sprintf("WireGuard keepalives: %d idle records of %d bytes", n, r.size)
		if n > 1 {
			c.flagged += fmt.Sprintf(", %s apart", end.Sub(c.run.last).Round(time.Second))
		}
		return
	}
	c.pending = &r
}

// exchange notes an occurrence of the exchange of sizes, the answer
// ending at end, and flags the connection at the wgRekeys-th a rekey
// period after the one before.
func (m *wgRhythm) exchange(c *wgConn, sizes [2]int, end time.Time) {
	keep := m.rekey * 3 / 2
	if len(c.exchanges) > wgExchangesKept {
		for k, occ := range c.exchanges {
			if end.Sub(occ[len(occ)-1].at) > keep {
				delete(c.exchanges, k)
			}
		}
	}
	occ := c.exchanges[sizes]
	for len(occ) > 0 && end.Sub(occ[0].at) > keep {
		occ = occ[1:]
	}
	o := wgOccurrence{at: end, chain: 1}
	for _, e := range occ {
		if gap := end.Sub(e.at); gap >= m.rekey && e.chain+1 > o.chain {
			o.chain, o.gap = e.chain+1, gap
		}
	}
	if o.chain >= wgRekeys {
		c.flagged = fmt.Sprintf("WireGuard rekey: records of %d and %d bytes exchanged %d times, the last %s apart",
			sizes[0], sizes[1], o.chain, o.gap.Round(time.Second))
		return
	}
	// More answers to one record are one occurrence.
	if n := len(occ); n > 0 && end.Sub(occ[n-1].at) <= wgPairWindow {
		occ[n-1].chain = max(occ[n-1].chain, o.chain)
	} else {
		occ = append(occ, o)
	}
	c.exchanges[sizes] = occ
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
