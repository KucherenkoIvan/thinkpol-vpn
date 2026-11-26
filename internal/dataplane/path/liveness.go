package path

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"math/bits"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// Liveness of one link, as docs/design/path-liveness.md sets it out: acks
// in the frames prove that the far end reads what this end writes, so
// busy links need no probes, and idle links probe after a drawn wait.
//
// Until the far end shows it reads acks (a probe with flagReadsAcks, or
// a frame with seq and ack), a link writes the V1 frames and keeps the V1
// rule: a probe every probeEveryV1 while unanswered that long, closed
// deadAfterV1 after its last answer.
const (
	probeEveryV1 = 2 * time.Second
	deadAfterV1  = 6 * time.Second
	// closeGrace is how long a dead link waits for its close notice to
	// leave before it closes anyway (a write blocked on a stalled stream).
	closeGrace = 50 * time.Millisecond
	// reorderWindow is how far behind the newest seq read a frame may
	// come and still count as reordered: one further behind is from a new
	// link at the far end (a redial onto this one, its seq drawn afresh),
	// and its seq is acked from then on.
	reorderWindow = 1024
)

// liveness is a link's state for the rules; the link's lmu guards it.
// Times are node times (zero: never).
type liveness struct {
	acks bool // the far end reads acks: write frames with seq and ack

	first uint32 // the first seq this end writes

	// Serial numbers: latest is the newest seq written (first-1 before
	// any), highAck the newest ack read that counted, recv the newest seq
	// read (haveRecv once there is one to ack).
	latest, highAck, recv uint32
	haveRecv              bool

	clock   int64 // P: the latest answer, or the latest burst's first frame
	prev    int64 // the previous frame that expects an answer
	spacing int64 // S, drawn at each answer

	suspectAt int64 // the earliest standing deadline for an answer
	idleAt    int64 // the latest answer plus I

	probing    bool // suspect: probed, waiting up to T
	siblings   bool // the second probe goes to the siblings too
	secondSent bool
	secondAt   int64
	deadAt     int64

	closeAt  int64 // dead: closes then, notice sent or not
	closeWhy string

	srtt, rttvar int64 // probes' round trips; measured once one came back
	measured     bool

	lastProbe int64 // the V1 rule's cadence
}

// linkRand is a new link's source of draws: a generator of its own,
// seeded once from crypto/rand, or Options.Rand under the node's lock.
func (n *Node) linkRand() io.Reader {
	if n.opts.Rand != nil {
		return &lockedReader{mu: &n.randMu, r: n.opts.Rand}
	}
	var seed [32]byte
	_, _ = crand.Read(seed[:]) // it never fails: the program crashes first
	return rand.NewChaCha8(seed)
}

type lockedReader struct {
	mu *sync.Mutex
	r  io.Reader
}

func (r *lockedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return io.ReadFull(r.r, p)
}

// drawLocked fills b from the link's draws. A failing Options.Rand
// panics: zeros would draw every range's bottom, a fixed rhythm.
func (l *link) drawLocked(b []byte) {
	if _, err := io.ReadFull(l.rand, b); err != nil {
		panic("path: Options.Rand failed: " + err.Error())
	}
}

// within maps u uniformly onto r: from r.Min up to r.Max.
func within(r Range, u uint32) int64 {
	hi, _ := bits.Mul64(uint64(r.Max-r.Min), uint64(u)<<32)
	return int64(r.Min) + int64(hi)
}

// initLiveness starts the rules for a link created at now, before anyone
// else can see it.
func (l *link) initLiveness(now int64) {
	var b [12]byte
	l.drawLocked(b[:])
	first := binary.BigEndian.Uint32(b[:4])
	l.lv = liveness{first: first, latest: first - 1, highAck: first - 1, clock: now}
	l.waitsLocked(now, b[4:])
}

// waitsLocked draws S and the idle wait from now, from 8 random bytes.
func (l *link) waitsLocked(now int64, b []byte) {
	o := &l.node.opts
	s := Range{o.Burst.Min, max(o.Burst.Min, o.Burst.Max-time.Duration(l.delay))}
	l.lv.spacing = within(s, binary.BigEndian.Uint32(b[:4]))
	l.lv.idleAt = now + within(l.idle, binary.BigEndian.Uint32(b[4:8]))
}

// responseLocked is R: the probes' smoothed round trip plus four
// deviations, clamped to Options.Response; its top until measured.
func (l *link) responseLocked() int64 {
	r := l.node.opts.Response
	if !l.lv.measured {
		return int64(r.Max)
	}
	return min(max(l.lv.srtt+4*l.lv.rttvar, int64(r.Min)), int64(r.Max))
}

// holdLocked is T: a probe's longest round trip, held at both ends and
// shaped by both.
func (l *link) holdLocked() int64 {
	return 2*int64(l.node.opts.ControlHold) + l.delay + l.responseLocked()
}

func (l *link) sampleLocked(rtt int64) {
	lv := &l.lv
	if !lv.measured {
		lv.srtt, lv.rttvar, lv.measured = rtt, rtt/2, true
	} else {
		d := lv.srtt - rtt
		if d < 0 {
			d = -d
		}
		lv.rttvar = (3*lv.rttvar + d) / 4
		lv.srtt = (7*lv.srtt + rtt) / 8
	}
	l.rtt.Store(max(lv.srtt, 1))
}

// ackAnswerLocked reports whether ack makes a frame an answer: newer than
// any ack before, or covering the latest frame written. An ack ahead of
// that frame, or 2³¹ behind it, is ignored.
func (l *link) ackAnswerLocked(ack uint32) bool {
	lv := &l.lv
	if d := int32(ack - lv.latest); d > 0 || d == math.MinInt32 {
		return false
	}
	if int32(ack-lv.highAck) > 0 {
		lv.highAck = ack
		return true
	}
	return ack == lv.latest
}

// answeredLocked takes an answer read at now: the clock restarts, every
// deadline is cleared, S and I are drawn anew. It reports whether the link
// came up with it.
func (l *link) answeredLocked(now int64) bool {
	var b [8]byte
	l.drawLocked(b[:])
	lv := &l.lv
	l.lastAnswer.Store(now)
	lv.clock = now
	lv.suspectAt, lv.probing, lv.secondAt, lv.deadAt = 0, false, 0, 0
	l.waitsLocked(now, b[:])
	if l.upSince.Load() == 0 {
		l.upSince.Store(now)
		return true
	}
	return false
}

// wroteLocked applies the busy rules to a frame that expects an answer,
// written at w: one written S after both the clock and the previous such
// frame opens a burst, due within S + R; one written S after the clock
// within a burst is due within R. A deadline stands until an answer.
func (l *link) wroteLocked(w int64) {
	lv := &l.lv
	if !lv.acks {
		return
	}
	s := lv.spacing
	switch {
	case w-lv.clock >= s && w-lv.prev >= s:
		lv.clock = w
		lv.due(w + s + l.responseLocked())
	case w-lv.clock >= s:
		lv.due(w + l.responseLocked())
	}
	lv.prev = w
}

func (lv *liveness) due(t int64) {
	if lv.suspectAt == 0 || t < lv.suspectAt {
		lv.suspectAt = t
	}
}

// suspectLocked starts probing at now: dead unless an answer comes within
// T, a second probe at T/2 (to the siblings too, if siblings).
func (l *link) suspectLocked(now int64, siblings bool) {
	t := l.holdLocked()
	lv := &l.lv
	lv.probing, lv.siblings, lv.secondSent = true, siblings, false
	lv.secondAt, lv.deadAt = now+t/2, now+t
}

// nextLocked is the earliest pending deadline, or 0.
func (l *link) nextLocked() int64 {
	lv := &l.lv
	if lv.closeAt != 0 {
		return lv.closeAt
	}
	var next int64
	at := func(t int64) {
		if t != 0 && (next == 0 || t < next) {
			next = t
		}
	}
	answered := l.lastAnswer.Load()
	if answered == 0 {
		at(l.created + int64(l.node.opts.DialTimeout))
	}
	switch {
	case !lv.acks:
		if answered != 0 {
			at(answered + int64(deadAfterV1))
		}
		at(max(lv.lastProbe, answered) + int64(probeEveryV1))
	case lv.probing:
		if !lv.secondSent {
			at(lv.secondAt)
		}
		at(lv.deadAt)
	default:
		at(lv.suspectAt)
		at(lv.idleAt)
	}
	return next
}

// armLocked sets the link's one timer to its earliest deadline.
func (l *link) armLocked(now int64) {
	next := l.nextLocked()
	if next == 0 || next == l.armed || l.closed() {
		return
	}
	l.armed = next
	d := time.Duration(max(next-now, 0))
	if l.timer == nil {
		l.timer = l.node.opts.afterFunc(d, l.fire)
		return
	}
	l.timer.Reset(d)
}

// actions are what a deadline asks for, done outside the link's lock.
type actions struct {
	probe, siblings, notice bool
	close                   string
}

// fire runs when the link's timer goes off.
func (l *link) fire() {
	now := l.node.now()
	l.lmu.Lock()
	l.armed = 0
	a := l.checkLocked(now)
	l.armLocked(now)
	l.lmu.Unlock()
	l.act(a, now)
}

// checkLocked applies the deadlines due at now.
func (l *link) checkLocked(now int64) actions {
	lv := &l.lv
	var a actions
	answered := l.lastAnswer.Load()
	switch {
	case lv.closeAt != 0:
		if now >= lv.closeAt {
			a.close = lv.closeWhy
		}
	case answered == 0 && now-l.created >= int64(l.node.opts.DialTimeout):
		a.close = "no answer within " + l.node.opts.DialTimeout.String()
	case !lv.acks:
		switch {
		case answered != 0 && now-answered >= int64(deadAfterV1):
			a.close = "no answer to its probes within " + deadAfterV1.String()
		case now-max(lv.lastProbe, answered) >= int64(probeEveryV1):
			a.probe = true
		}
	case lv.probing:
		switch {
		case now >= lv.deadAt:
			lv.closeAt, lv.closeWhy = now+int64(closeGrace), "no answer within T of turning suspect"
			a.notice = true
		case !lv.secondSent && now >= lv.secondAt:
			lv.secondSent = true
			a.probe, a.siblings = true, lv.siblings
		}
	case lv.suspectAt != 0 && now >= lv.suspectAt, now >= lv.idleAt:
		l.suspectLocked(now, true)
		a.probe = true
	}
	return a
}

func (l *link) act(a actions, now int64) {
	switch {
	case a.close != "":
		l.close(a.close, nil)
		return
	case a.notice:
		l.sendNotice()
	}
	if a.probe {
		l.probe(now)
	}
	if a.siblings {
		for _, s := range l.node.siblings(l) {
			s.nudge(l.node.now(), false)
		}
	}
}

// nudge makes an up link that reads acks suspect at once, unless it is
// already: siblings get one when a link's second probe goes out (no
// siblings of their own), and hints make a link silent for R suspect.
func (l *link) nudge(now int64, siblings bool) {
	l.lmu.Lock()
	lv := &l.lv
	if !lv.acks || lv.probing || lv.closeAt != 0 || l.lastAnswer.Load() == 0 {
		l.lmu.Unlock()
		return
	}
	l.suspectLocked(now, siblings)
	l.armLocked(now)
	l.lmu.Unlock()
	l.probe(now)
}

// hint makes the link suspect if it has been silent for R: frames of its
// neighbor, or of a peer it carried, now arrive another way.
func (l *link) hint(now int64) {
	l.lmu.Lock()
	silent := now-l.lastIn.Load() >= l.responseLocked()
	l.lmu.Unlock()
	if silent {
		l.nudge(now, true)
	}
}

// onFrame takes a frame read at now for liveness: off is where its seq
// and ack sit (-1: a V1 frame without them), probeSent when the probe
// a reply answers was sent (0: it answers none).
func (l *link) onFrame(now int64, f []byte, off int, probeSent int64) {
	l.lmu.Lock()
	lv := &l.lv
	answered := probeSent != 0
	if answered {
		l.sampleLocked(now - probeSent)
	}
	if off >= 0 {
		lv.acks = true
		seq, ack := binary.BigEndian.Uint32(f[off:]), binary.BigEndian.Uint32(f[off+4:])
		if d := int32(seq - lv.recv); !lv.haveRecv || d > 0 || d < -reorderWindow {
			lv.recv, lv.haveRecv = seq, true
		}
		if l.ackAnswerLocked(ack) {
			answered = true
		}
	}
	up := answered && lv.closeAt == 0 && l.answeredLocked(now)
	l.armLocked(now)
	l.lmu.Unlock()
	if up {
		l.node.opts.Log.Info("link up", l.logAttrs(now)...)
	}
}

// readsAcks takes a V1 probe that says its sender reads acks: the link
// switches to frames with seq and ack, acking the sender's first seq less
// one (the token's first four bytes) until a frame with a seq arrives. On
// a link that reads seqs already, the probe is a new link's at the far end
// (a redial onto this one): its seq starts over from there.
func (l *link) readsAcks(token []byte, now int64) {
	l.lmu.Lock()
	lv := &l.lv
	lv.acks = true
	lv.recv, lv.haveRecv = binary.BigEndian.Uint32(token), true
	l.armLocked(now)
	l.lmu.Unlock()
}

// sendNotice queues a close notice; the writer closes the link once it is
// out, or closeGrace closes it without.
func (l *link) sendNotice() {
	b := getBuf()
	f := (*b)[:probeSize]
	clear(f)
	f[0], f[1] = kindProbe, flagReadsAcks|flagClosing
	*b = f
	if !l.sendControl(b) {
		l.close(l.closeReason(), nil)
	}
}

// closeReason is why a dead link closes.
func (l *link) closeReason() string {
	l.lmu.Lock()
	defer l.lmu.Unlock()
	return l.lv.closeWhy
}

// siblings are the links a suspect link's second probe also goes to: its
// neighbor's other links, and for each peer and route whose current hop
// is its neighbor, the next up candidate's link.
func (n *Node) siblings(l *link) []*link {
	var out []*link
	add := func(s *link) {
		if s != nil && s != l && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, s := range l.nb.all() {
		add(s)
	}
	next := func(current NodeID, hops []NodeID) {
		if current != l.nb.id {
			return
		}
		for _, h := range hops {
			if h == current {
				continue
			}
			if nb := n.lookupNeighbor(h); nb != nil {
				if s, up := nb.pick(); up {
					add(s)
					return
				}
			}
		}
	}
	for _, ps := range *n.peers.Load() {
		ps.mu.Lock()
		cur := ps.current
		ps.mu.Unlock()
		next(cur, *ps.hops.Load())
	}
	for _, rs := range *n.routes.Load() {
		rs.mu.Lock()
		cur, hops := rs.current, rs.hops
		rs.mu.Unlock()
		next(cur, hops)
	}
	return out
}
