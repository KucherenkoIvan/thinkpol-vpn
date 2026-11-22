package path

import (
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// The liveness tests run two nodes over a pipe on a fake clock: the test
// steps the clock, the links' timers go off as it passes them, and each
// direction of the pipe can lose, hold back, refuse or answer frames. They
// run in a synctest bubble (bubble), where the harness waits after each
// timer and step until every frame in flight has been handled.

// bubble runs f, a liveness test's body, in a synctest bubble.
func bubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	synctest.Test(t, f)
}

type lclock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*ltimer
}

type ltimer struct {
	c  *lclock
	at time.Time // zero: stopped or gone off
	f  func()
}

func (c *lclock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lclock) AfterFunc(d time.Duration, f func()) timer {
	t := &ltimer{c: c, f: f}
	t.Reset(d)
	return t
}

func (t *ltimer) Reset(d time.Duration) bool {
	c := t.c
	c.mu.Lock()
	defer c.mu.Unlock()
	was := !t.at.IsZero()
	t.at = c.now.Add(max(d, 0))
	if !was {
		c.timers = append(c.timers, t)
	}
	return was
}

func (t *ltimer) Stop() bool {
	c := t.c
	c.mu.Lock()
	defer c.mu.Unlock()
	was := !t.at.IsZero()
	t.at = time.Time{}
	c.timers = slices.DeleteFunc(c.timers, func(x *ltimer) bool { return x == t })
	return was
}

// add moves the clock on by d, running the timers due meanwhile at their
// own times, earliest first.
func (c *lclock) add(d time.Duration) {
	c.mu.Lock()
	end := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var due *ltimer
		for _, t := range c.timers {
			if !t.at.After(end) && (due == nil || t.at.Before(due.at)) {
				due = t
			}
		}
		if due == nil {
			c.now = end
			c.mu.Unlock()
			return
		}
		c.now = due.at
		due.at = time.Time{}
		c.timers = slices.DeleteFunc(c.timers, func(x *ltimer) bool { return x == due })
		c.mu.Unlock()
		due.f()
		synctest.Wait() // what the timer queued goes out at its time
	}
}

// constRand is an Options.Rand of one byte repeated: 0x00 draws every
// range's bottom, 0xff its top (and starts seq at 2³²-1, so it wraps at
// once).
type constRand byte

func (c constRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

// seededRand is a deterministic Options.Rand that spreads its draws.
type seededRand struct{ r *rand.ChaCha8 }

func newSeededRand(seed byte) *seededRand { return &seededRand{rand.NewChaCha8([32]byte{seed})} }

func (s *seededRand) Read(p []byte) (int, error) { return s.r.Read(p) }

// wire is one direction of a pipe; mu also guards its writer's peer.
type wire struct {
	mu      sync.Mutex
	lost    bool
	delay   time.Duration
	drop    func(f []byte) bool // frames that vanish
	limit   int                 // longer frames are refused as too long; 0: none
	written []record
}

type record struct {
	at time.Duration // since the harness started
	f  []byte
}

// pend is one end of a pipe: a datagram transport.Link.
type pend struct {
	h       *harness
	out     *wire
	peer    *pend
	in      chan []byte
	done    chan struct{}
	once    sync.Once
	shaping transport.Shaping
	// respond, if set, stands in for a node at this end: it gets what
	// arrives and returns what to send back.
	respond func(f []byte) [][]byte
}

func (e *pend) ReadPacket(p []byte) (int, error) {
	select {
	case f := <-e.in:
		return copy(p, f), nil
	case <-e.done:
		return 0, net.ErrClosed
	}
}

func (e *pend) WritePacket(p []byte) error {
	select {
	case <-e.done:
		return net.ErrClosed
	default:
	}
	w := e.out
	w.mu.Lock()
	if w.limit > 0 && len(p) > w.limit {
		w.mu.Unlock()
		return transport.ErrPacketTooLong
	}
	f := slices.Clone(p)
	w.written = append(w.written, record{at: e.h.elapsed(), f: f})
	lost := w.lost || w.drop != nil && w.drop(f)
	delay, peer := w.delay, e.peer
	w.mu.Unlock()
	if lost {
		return nil
	}
	if delay > 0 {
		e.h.clock.AfterFunc(delay, func() { peer.arrive(f) })
		return nil
	}
	peer.arrive(f)
	return nil
}

func (e *pend) arrive(f []byte) {
	if e.respond != nil {
		for _, r := range e.respond(f) {
			_ = e.WritePacket(r)
		}
		return
	}
	select {
	case e.in <- f:
	default:
	}
}

func (e *pend) Close() error {
	e.once.Do(func() { close(e.done) })
	return nil
}

func (e *pend) LocalAddr() net.Addr  { return nil }
func (e *pend) RemoteAddr() net.Addr { return nil }

// Shaping makes the end a shapedLink, as an accepted link would say.
func (e *pend) Shaping() transport.Shaping { return e.shaping }

// harness is nodes A (id 1, the leader) and B (id 2) on a fake clock, in
// a bubble.
type harness struct {
	t      *testing.T
	clock  *lclock
	start  time.Time
	step   time.Duration
	a, b   *Node
	nodeAt map[*Node]string
}

func newHarness(t *testing.T, tune func(*Options)) *harness {
	t.Helper()
	c := &lclock{now: time.Unix(1_000_000, 0)}
	h := &harness{t: t, clock: c, start: c.now, step: 20 * time.Millisecond, nodeAt: map[*Node]string{}}
	opts := func() Options {
		o := Options{Now: c.Now, afterFunc: c.AfterFunc, watchEvery: time.Hour, Rand: constRand(0)}
		if tune != nil {
			tune(&o)
		}
		return o
	}
	var err error
	if h.a, err = NewNode(NodeID{1}, opts()); err != nil {
		t.Fatal(err)
	}
	if h.b, err = NewNode(NodeID{2}, opts()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = h.a.Close()
		_ = h.b.Close()
	})
	return h
}

func (h *harness) elapsed() time.Duration { return h.clock.Now().Sub(h.start) }

// pipe returns two connected ends and the wires they write on: xy carries
// what x writes, yx what y writes.
func (h *harness) pipe() (x, y *pend, xy, yx *wire) {
	xy, yx = &wire{}, &wire{}
	x = &pend{h: h, out: xy, in: make(chan []byte, 1024), done: make(chan struct{})}
	y = &pend{h: h, out: yx, in: make(chan []byte, 1024), done: make(chan struct{})}
	x.peer, y.peer = y, x
	return x, y, xy, yx
}

// link joins A and B with one link of the named transport, A dialing with
// shaping s (B's end says the same), and waits until both ends are up and
// write seq and ack.
func (h *harness) link(transportName string, s transport.Shaping) (la, lb *link, ab, ba *wire) {
	h.t.Helper()
	x, y, ab, ba := h.pipe()
	y.shaping = s
	la = h.a.addLink(h.b.id, x, true, transportName, 0, s)
	lb = h.b.addLink(h.a.id, y, false, transportName, -1, transport.Shaping{})
	h.until("the link up", 5*time.Second, func() bool { return la.up() && lb.up() && la.acking() && lb.acking() }, nil)
	h.run(h.step, nil) // the frames that brought it up are behind
	return la, lb, ab, ba
}

// acking says whether l writes seq and ack: its far end reads acks.
func (l *link) acking() bool {
	l.lmu.Lock()
	defer l.lmu.Unlock()
	return l.lv.acks
}

// reattach replaces l, one end of a link, with a new link of l's node
// writing on the same wire to the same far end, as a redial or a restart
// lands on the far end's open udp link (udp's doc, "Links"): l closes
// without a notice, the far end's link carries on, and the new link draws
// its first seq afresh.
func (h *harness) reattach(l *link) *link {
	h.t.Helper()
	old := l.tl.(*pend)
	far := old.peer
	l.close("re-attached", nil)
	e := &pend{h: h, out: old.out, peer: far, in: make(chan []byte, 1024), done: make(chan struct{})}
	far.out.mu.Lock()
	far.peer = e
	far.out.mu.Unlock()
	return l.node.addLink(l.nb.id, e, l.dialed, l.transport, l.endpoint, transport.Shaping{})
}

// run steps the clock for d, calling each (if any) after every step.
func (h *harness) run(d time.Duration, each func()) {
	for done := time.Duration(0); done < d; done += h.step {
		h.clock.add(h.step)
		synctest.Wait()
		if each != nil {
			each()
		}
	}
}

// until steps the clock until cond holds and returns how long that took;
// it fails the test after limit.
func (h *harness) until(what string, limit time.Duration, cond func() bool, each func()) time.Duration {
	h.t.Helper()
	for took := time.Duration(0); ; took += h.step {
		if cond() {
			return took
		}
		if took > limit {
			h.t.Fatalf("%s: not within %v", what, limit)
		}
		h.clock.add(h.step)
		synctest.Wait()
		if each != nil {
			each()
		}
	}
}

// data queues a packet from l's node to the far node: a message the far
// node has no peer for, which it counts as UnknownPeer.
func data(l *link) {
	b := getBuf()
	f := (*b)[:HeaderSize+100]
	putHeader(f, header{hopLimit: 8, dst: l.nb.id, src: l.node.id})
	clear(f[headerSizeV1:])
	f[HeaderSize] = wgData
	*b = f
	l.send(b)
}

// sinceAnswer is how long ago l's latest answer came.
func (h *harness) sinceAnswer(l *link) time.Duration {
	return time.Duration(l.node.now() - l.lastAnswer.Load())
}

// probes counts the probes written on w from on (close notices too).
func probes(w *wire, from time.Duration) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, r := range w.written {
		if r.at >= from && r.f[0] == kindProbe {
			n++
		}
	}
	return n
}

// kinds lists the frames written on w from on: kind and length.
func kinds(w *wire, from time.Duration) [][2]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out [][2]int
	for _, r := range w.written {
		if r.at >= from {
			out = append(out, [2]int{int(r.f[0]), len(r.f)})
		}
	}
	return out
}

// olderNode answers like a node from before acks: a V1 probe comes back
// with its kind changed and everything else copied; anything else it
// can't read and drops.
func olderNode(f []byte) [][]byte {
	if f[0] == kindProbe && len(f) == probeSizeV1 {
		r := slices.Clone(f)
		r[0] = kindProbeReply
		return [][]byte{r}
	}
	return nil
}

func isNotice(f []byte) bool {
	return f[0] == kindProbe && len(f) == probeSize && f[1]&flagClosing != 0
}

// v1Packet is a V1 packet from src to dst with a message of n bytes.
func v1Packet(src, dst NodeID, n int) []byte {
	f := make([]byte, headerSizeV1+n)
	f[0], f[1] = kindPacketV1, 8
	copy(f[2:10], dst[:])
	copy(f[10:18], src[:])
	f[headerSizeV1] = wgData
	return f
}
