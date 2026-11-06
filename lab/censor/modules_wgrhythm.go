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

// WireGuard's message sizes (the WireGuard paper, section 5.4): a
// handshake initiation, its response, and a keepalive, the transport
// message with nothing in it. A transport that carries each message in a
// TLS record of its own adds the same overhead to every one, so a record
// pair whose sizes differ by wgInitiation-wgResponse gives the overhead
// away, and with it the size of a keepalive record.
const (
	wgInitiation = 148
	wgResponse   = 92
	wgKeepalive  = 32
)

const (
	// wgMaxOverhead bounds the bytes a transport adds to a WireGuard
	// message in its record: TLS 1.3's AEAD tag and content type (17) and
	// framing of its own, with room to spare.
	wgMaxOverhead = 128
	// wgPairWindow is how soon after an initiation-sized record the
	// response-sized one must come the other way: a round trip and the
	// responder's work.
	wgPairWindow = 2 * time.Second
	// wgRecentRecords caps the records of each direction kept to pair
	// with, so a fast flow's state stays small.
	wgRecentRecords = 32
	// wgPairsKept caps the handshake pairs of each overhead kept to time
	// the next against: a retried initiation adds one.
	wgPairsKept = 8
)

// wgRhythm flags a TLS connection that carries WireGuard with its rhythm
// showing (docs/design/milestones.md, M2): the handshake pair WireGuard
// sends every 2 minutes it has data to send, and fixed-size keepalive
// records. It frames each direction's TLS records from the stream and
// looks at application-data records only: their sizes, their direction
// and when they ended. A handshake pair is an initiation-sized record one
// way followed within wgPairWindow by a response-sized one the other way,
// both with the same overhead. The connection shows the rhythm, and is
// decided with the module's verdict from then on, both ways, when
//
//   - two handshake pairs of one overhead are a rekey period apart, from
//     the period to half as much again past it (WireGuard rekeys after 2
//     minutes when it sends, and up to 45 s later when it only receives),
//     or
//   - a handshake pair's overhead makes keepalive-sized records of which
//     the connection has carried at least keepalives, either way.
//
// Flow shape beyond that (size distributions, bursts) is not its business
// (owner, 2026-11-07). A stream it can't frame as TLS from its first byte
// is never judged: not TLS, joined midstream, or with bytes the module
// wasn't shown (a module before it dropped their packet).
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
	// pairs holds when each overhead's latest handshake pairs ended,
	// wgPairsKept at most.
	pairs map[int][]time.Time
	// small counts application-data records by size, up to the largest a
	// keepalive record can be.
	small   map[int]int
	flagged string
}

// wgDirection frames one direction's TLS records.
type wgDirection struct {
	header   []byte // a record header split over packets, so far
	body     int    // bytes of the current record's body still to come
	size     int    // the current record's length
	appData  bool   // the current record is application data
	notTLS   bool
	recent   []wgRecord
	consumed uint64 // stream bytes framed so far
}

type wgRecord struct {
	size int
	end  time.Time
}

// newWGRhythm builds the module from its settings:
//
//	{"verdict": "drop", "rekey": "120s", "keepalives": 3}
//
// verdict is drop (default) or reset; rekey is WireGuard's rekey period
// (a lab test shortens it to see two rekeys quickly), keepalives the
// keepalive-sized records that, with a handshake pair, show the rhythm.
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

func (m *wgRhythm) Inspect(_ *Packet, f *Flow) Decision {
	if f.Stream == nil {
		return Decision{Verdict: Accept}
	}
	c, dir := m.conn(f)
	if c.flagged == "" {
		m.read(c, dir, f)
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
	c := &wgConn{pairs: map[int][]time.Time{}, small: map[int]int{}}
	c.flows[0] = f
	m.conns[f.Key] = c
	return c, 0
}

// read frames the records the flow's latest packet completed, and judges
// each.
func (m *wgRhythm) read(c *wgConn, dir int, f *Flow) {
	d := &c.dirs[dir]
	if d.notTLS {
		return
	}
	if f.Stream.Midstream() || f.Stream.Delivered() != d.consumed+uint64(len(f.Stream.Fresh())) {
		d.notTLS = true
		return
	}
	b := f.Stream.Fresh()
	d.consumed += uint64(len(b))
	for len(b) > 0 {
		if d.body == 0 {
			n := min(5-len(d.header), len(b))
			d.header, b = append(d.header, b[:n]...), b[n:]
			if len(d.header) < 5 {
				return
			}
			h := d.header
			d.header = d.header[:0]
			if h[0] < 0x14 || h[0] > 0x17 || h[1] != 3 || h[2] > 4 {
				d.notTLS = true
				return
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
}

// record judges one whole record of direction dir that ended at end.
func (m *wgRhythm) record(c *wgConn, dir int, d *wgDirection, end time.Time) {
	if !d.appData || c.flagged != "" {
		return
	}
	size := d.size
	if size <= wgKeepalive+wgMaxOverhead {
		c.small[size]++
	}
	// A response-sized record pairs with an initiation-sized one the
	// other way.
	if o := size - wgResponse; o >= 0 && o <= wgMaxOverhead {
		other := &c.dirs[1-dir]
		for _, r := range other.recent {
			if r.size == size+wgInitiation-wgResponse && end.Sub(r.end) <= wgPairWindow {
				m.pair(c, o, end)
				break
			}
		}
	}
	d.recent = append(d.recent, wgRecord{size, end})
	for len(d.recent) > 0 && (len(d.recent) > wgRecentRecords || end.Sub(d.recent[0].end) > wgPairWindow) {
		d.recent = d.recent[1:]
	}
	if c.flagged == "" {
		for o := range c.pairs {
			if n := c.small[o+wgKeepalive]; n >= m.keepalives {
				c.flagged = fmt.Sprintf("WireGuard keepalives: %d records of %d bytes beside a handshake pair", n, o+wgKeepalive)
				return
			}
		}
	}
}

// pair notes a handshake pair of overhead o that ended at end.
func (m *wgRhythm) pair(c *wgConn, o int, end time.Time) {
	for _, last := range c.pairs[o] {
		if gap := end.Sub(last); gap >= m.rekey && gap <= m.rekey*3/2 {
			c.flagged = fmt.Sprintf("WireGuard rekey: handshake pairs of %d and %d bytes %s apart",
				o+wgInitiation, o+wgResponse, gap.Round(time.Second))
			return
		}
	}
	c.pairs[o] = append(c.pairs[o], end)
	if len(c.pairs[o]) > wgPairsKept {
		c.pairs[o] = c.pairs[o][1:]
	}
}
