package path

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// The bounds below are docs/design/path-liveness.md's, on an unshaped
// link unless a test says otherwise: S from 0.5 s to 1.5 s, R from 250 ms
// (the fake clock's round trips are near zero) to 1 s when a test pins
// it there, T = 2·500 ms + D + R.

// slowest pins every draw at its top and R at 1 s: the design's worst
// cases.
func slowest(o *Options) {
	o.Rand = constRand(0xff)
	o.Response = Range{time.Second, time.Second}
}

// near checks got against want, give or take tol.
func near(t *testing.T, what string, got, want, tol time.Duration) {
	t.Helper()
	if got < want-tol || got > want+tol {
		t.Errorf("%s after %v, want %v ± %v", what, got, want, tol)
	}
}

// closedAfterAnswer steps the clock until l closes and returns how long
// after its latest answer that was.
func (h *harness) closedAfterAnswer(l *link, limit time.Duration, each func()) time.Duration {
	h.t.Helper()
	var at time.Duration
	h.until("the link closed", limit, func() bool {
		if l.closed() {
			return true
		}
		at = h.sinceAnswer(l) + h.step
		return false
	}, each)
	return at
}

// Under two-way traffic acks prove both directions: no probe goes either
// way, across seq's wrap too.
func TestBusyLinksSendNoProbes(t *testing.T) {
	for _, r := range []struct {
		name string
		rand constRand
	}{{"seq from 0", 0x00}, {"seq from 2³²-1", 0xff}} {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, func(o *Options) { o.Rand = r.rand })
			la, lb, ab, ba := h.link("udp", transport.Shaping{})
			from := h.elapsed()
			h.run(30*time.Second, func() { data(la); data(lb) })
			if n := probes(ab, from) + probes(ba, from); n != 0 {
				t.Fatalf("%d probes under two-way traffic", n)
			}
			if !la.up() || !lb.up() {
				t.Fatal("the link went down under two-way traffic")
			}
		})
	}
}

// A seq that wraps keeps counting: two-way traffic across 2³² sends no
// probes.
func TestSeqWrapsWithoutProbes(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.Rand = seqFrom(math.MaxUint32 - 200) })
	la, lb, ab, ba := h.link("udp", transport.Shaping{})
	from := h.elapsed()
	h.run(10*time.Second, func() { data(la); data(lb) })
	if n := probes(ab, from) + probes(ba, from); n != 0 {
		t.Fatalf("%d probes under two-way traffic across the wrap", n)
	}
	la.lmu.Lock()
	latest := la.lv.latest
	la.lmu.Unlock()
	if latest > 1000 {
		t.Fatalf("seq at %d: never wrapped", latest)
	}
}

// seqFrom is an Options.Rand that starts every link's seq at s and draws
// every range's bottom.
type seqFrom uint32

func (s seqFrom) Read(p []byte) (int, error) {
	clear(p)
	if len(p) == 12 { // initLiveness: the first seq, then S and I
		binary.BigEndian.PutUint32(p, uint32(s))
	}
	return len(p), nil
}

// The answer rule, in serial arithmetic: newer than any ack before, or
// covering the latest frame; an ack ahead of it or 2³¹ behind is ignored.
func TestTheAnswerRule(t *testing.T) {
	for _, tc := range []struct {
		name            string
		latest, highAck uint32
		acks            []uint32
		want            []bool
	}{
		{"newer, then stale", 5, 3, []uint32{4, 4}, []bool{true, false}},
		{"covers the latest, again", 5, 5, []uint32{5, 5}, []bool{true, true}},
		{"ahead of the latest", 5, 3, []uint32{6}, []bool{false}},
		{"2³¹ behind", 5, 3, []uint32{5 + 1<<31}, []bool{false}},
		{"older than the newest ack", 5, 4, []uint32{3}, []bool{false}},
		{"across the wrap", 2, math.MaxUint32 - 1, []uint32{math.MaxUint32, 0, 1, 2}, []bool{true, true, true, true}},
		{"behind across the wrap", 1, 0, []uint32{math.MaxUint32}, []bool{false}},
	} {
		l := &link{lv: liveness{latest: tc.latest, highAck: tc.highAck}}
		for i, ack := range tc.acks {
			if got := l.ackAnswerLocked(ack); got != tc.want[i] {
				t.Errorf("%s: ack %d (latest %d): answer %v, want %v", tc.name, ack, tc.latest, got, tc.want[i])
			}
		}
	}
}

// A link that dies under two-way traffic, whichever direction broke, is
// closed at both ends S + R + T after their last answer: 2.0 s with the
// shortest draws, 4.5 s with the longest.
func TestDeadUnderTrafficEitherWay(t *testing.T) {
	for _, tc := range []struct {
		name string
		tune func(*Options)
		want time.Duration
	}{
		{"shortest", nil, 2 * time.Second},
		{"longest", slowest, 4500 * time.Millisecond},
	} {
		for _, lost := range []string{"A to B", "B to A"} {
			t.Run(tc.name+", "+lost+" lost", func(t *testing.T) {
				t.Parallel()
				h := newHarness(t, tc.tune)
				la, lb, ab, ba := h.link("udp", transport.Shaping{})
				traffic := func() {
					data(la)
					data(lb)
				}
				h.run(3*time.Second, traffic)
				w := ab
				if lost == "B to A" {
					w = ba
				}
				w.mu.Lock()
				w.lost = true
				w.mu.Unlock()
				var atA, atB time.Duration
				h.until("both ends closed", 10*time.Second, func() bool { return la.closed() && lb.closed() }, func() {
					traffic()
					if atA == 0 && la.closed() {
						atA = time.Duration(la.node.now() - la.lastAnswer.Load())
					}
					if atB == 0 && lb.closed() {
						atB = time.Duration(lb.node.now() - lb.lastAnswer.Load())
					}
				})
				tol := 3 * h.step
				near(t, "A closed", atA, tc.want, tol)
				near(t, "B closed", atB, tc.want, tol)
			})
		}
	}
}

// A receive-only end whose sending side broke hears the far end's close
// notice within the busy bound; without the notice it finds the link dead
// by the idle rule, I + T after its last answer (26 s on reality).
func TestReceiveOnlyEnd(t *testing.T) {
	for _, notice := range []bool{true, false} {
		t.Run(fmt.Sprintf("notice %v", notice), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, slowest)
			h.step = 50 * time.Millisecond
			la, lb, ab, ba := h.link("reality", transport.Shaping{})
			h.run(3*time.Second, func() { data(la) })
			ba.mu.Lock()
			ba.lost = true
			ba.mu.Unlock()
			if !notice {
				ab.mu.Lock()
				ab.drop = isNotice
				ab.mu.Unlock()
			}
			lost := h.elapsed()
			sending := func() {
				if !la.closed() {
					data(la)
				}
			}
			if notice {
				h.until("B closed", 30*time.Second, lb.closed, sending)
				if took := h.elapsed() - lost; took > 4500*time.Millisecond+3*h.step {
					t.Fatalf("B closed %v after its sending side broke, want within 4.5 s", took)
				}
				return
			}
			got := h.closedAfterAnswer(lb, 40*time.Second, sending)
			near(t, "B closed", got, 26*time.Second, 3*h.step)
		})
	}
}

// A sparse sender, a frame every X s each answered at once until the link
// goes deaf, is found X s plus 2.0–4.5 s after its last answer. On reality,
// whose idle wait (8 s at least) is longer than every X here: on udp an X
// past 5 s can meet an idle probe first, which finds the link sooner.
func TestSparseSender(t *testing.T) {
	for _, x := range []time.Duration{2 * time.Second, 5 * time.Second, 7 * time.Second} {
		for _, tc := range []struct {
			name string
			tune func(*Options)
			want time.Duration
		}{
			{"shortest", nil, 2 * time.Second},
			{"longest", slowest, 4500 * time.Millisecond},
		} {
			t.Run(fmt.Sprintf("X %v, %s", x, tc.name), func(t *testing.T) {
				t.Parallel()
				h := newHarness(t, tc.tune)
				la, lb, ab, ba := h.link("reality", transport.Shaping{})
				var next time.Duration
				var seen uint64
				poll := func() {
					if h.elapsed() >= next && !la.closed() {
						data(la)
						next = h.elapsed() + x
					}
					if n := h.b.counters.unknownPeer.Load(); n != seen && !lb.closed() {
						seen = n
						data(lb) // the response
					}
				}
				h.run(3*x, poll)
				before := probes(ab, 0)
				h.run(2*x, poll)
				if n := probes(ab, 0) - before; n != 0 {
					t.Errorf("%d probes while every frame was answered", n)
				}
				for _, w := range []*wire{ab, ba} {
					w.mu.Lock()
					w.lost = true
					w.mu.Unlock()
				}
				got := h.closedAfterAnswer(la, 3*x+10*time.Second, poll)
				near(t, "A closed", got, x+tc.want, 4*h.step)
			})
		}
	}
}

// A SYN sent 0.4 s after an answer, with S at 1.5 s, and its retries 1 s
// and then 2 s apart: only the second retry opens a burst, so the link is
// found 7.9 s after the answer (the design's ≤ 8.0 s).
func TestSYNAfterAnAnswer(t *testing.T) {
	h := newHarness(t, slowest)
	la, lb, ab, ba := h.link("udp", transport.Shaping{})
	h.run(time.Second, func() { data(la); data(lb) })
	h.run(2*time.Second, nil) // both quiet: the next frame opens a burst
	data(la)
	data(lb)
	h.run(h.step, nil)
	for _, w := range []*wire{ab, ba} {
		w.mu.Lock()
		w.lost = true
		w.mu.Unlock()
	}
	answer := la.lastAnswer.Load()
	sends := []time.Duration{400 * time.Millisecond, 1400 * time.Millisecond, 3400 * time.Millisecond}
	got := h.closedAfterAnswer(la, 15*time.Second, func() {
		since := time.Duration(la.node.now() - answer)
		if len(sends) > 0 && since >= sends[0] {
			data(la)
			sends = sends[1:]
		}
	})
	near(t, "A closed", got, 7900*time.Millisecond, 3*h.step)
}

// Idle links probe after a wait drawn per transport: one exchange per
// draw, every interval within the transport's range, and spread: fewer
// than half of 30 consecutive pairs of intervals within 1 s of each other.
func TestIdleDrawsPerTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		r         Range
	}{
		{"reality", Range{8 * time.Second, 24 * time.Second}},
		{"udp", Range{5 * time.Second, 14 * time.Second}},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			t.Parallel()
			seed := byte(0)
			h := newHarness(t, func(o *Options) {
				seed++
				o.Rand = newSeededRand(seed)
			})
			h.step = 100 * time.Millisecond
			_, _, ab, ba := h.link(tc.transport, transport.Shaping{})
			from := h.elapsed()
			count := func() int { return probes(ab, from) + probes(ba, from) }
			h.until("32 exchanges", 40*tc.r.Max, func() bool { return count() >= 32 }, nil)
			var at []time.Duration
			for _, w := range []*wire{ab, ba} {
				w.mu.Lock()
				for _, r := range w.written {
					if r.at >= from && r.f[0] == kindProbe {
						at = append(at, r.at)
					}
				}
				w.mu.Unlock()
			}
			slices.Sort(at)
			// Both ends' waits may run out within one trip of each other:
			// two probes, one exchange.
			var gaps []time.Duration
			for i := 1; i < len(at); i++ {
				if g := at[i] - at[i-1]; g >= time.Second {
					gaps = append(gaps, g)
				}
			}
			tol := 2 * h.step
			for _, g := range gaps {
				if g < tc.r.Min-tol || g > tc.r.Max+tol {
					t.Errorf("an idle exchange %v after the last, want within %v–%v", g, tc.r.Min, tc.r.Max)
				}
			}
			close := 0
			for i := 1; i <= 30 && i < len(gaps); i++ {
				if d := gaps[i] - gaps[i-1]; d > -time.Second && d < time.Second {
					close++
				}
			}
			if close >= 15 {
				t.Errorf("%d of 30 consecutive intervals within 1 s of each other: %v", close, gaps)
			}
		})
	}
}

// A dead idle link is found I + T after its last answer: 26 s on reality,
// 16 s on udp, with the longest draws.
func TestDeadIdleBound(t *testing.T) {
	for _, tc := range []struct {
		transport string
		want      time.Duration
	}{{"reality", 26 * time.Second}, {"udp", 16 * time.Second}} {
		t.Run(tc.transport, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, slowest)
			h.step = 50 * time.Millisecond
			la, lb, ab, ba := h.link(tc.transport, transport.Shaping{})
			for _, w := range []*wire{ab, ba} {
				w.mu.Lock()
				w.lost = true
				w.mu.Unlock()
			}
			var atB time.Duration
			got := h.closedAfterAnswer(la, 40*time.Second, func() {
				if atB == 0 && lb.closed() {
					atB = time.Duration(lb.node.now() - lb.lastAnswer.Load())
				}
			})
			near(t, "A closed", got, tc.want, 3*h.step)
			h.until("B closed", 5*time.Second, lb.closed, nil)
			if atB == 0 {
				atB = time.Duration(lb.node.now() - lb.lastAnswer.Load())
			}
			near(t, "B closed", atB, tc.want, 3*h.step)
		})
	}
}

// When a busy link and its idle sibling to the same neighbor die
// together, the busy link's second probe goes to the sibling too, which is
// found S + R + 1.5·T after the busy link's last answer (5.5 s), not after
// its own idle wait.
func TestDoubleFailureViaSiblings(t *testing.T) {
	h := newHarness(t, slowest)
	h.step = 50 * time.Millisecond
	la1, lb1, ab1, ba1 := h.link("udp", transport.Shaping{})
	la2, _, ab2, ba2 := h.link("udp", transport.Shaping{})
	traffic := func() {
		if !la1.closed() {
			data(la1)
		}
		if !lb1.closed() {
			data(lb1)
		}
	}
	h.run(3*time.Second, traffic)
	for _, w := range []*wire{ab1, ba1, ab2, ba2} {
		w.mu.Lock()
		w.lost = true
		w.mu.Unlock()
	}
	answer := la1.lastAnswer.Load()
	h.until("A's idle link closed", 30*time.Second, la2.closed, traffic)
	got := time.Duration(la2.node.now() - answer)
	if got > 5500*time.Millisecond+3*h.step {
		t.Fatalf("the idle sibling closed %v after the busy link's last answer, want within 5.5 s", got)
	}
}

// A shaped link (D = 2 s: both ends' MaxDelay of 1 s) stays up while each
// direction holds frames back 1 s, and dies max(4.5 s, 3.5 s + D) = 5.5 s
// after its last answer at either end (the accepting end learns D from its
// link).
func TestShapedLink(t *testing.T) {
	h := newHarness(t, slowest)
	h.step = 50 * time.Millisecond
	s := transport.Shaping{BatchWindow: 500 * time.Millisecond, Jitter: 500 * time.Millisecond}
	la, lb, ab, ba := h.link("udp", s)
	if la.delay != int64(2*time.Second) || lb.delay != int64(2*time.Second) {
		t.Fatalf("D %v at A, %v at B; want 2s", time.Duration(la.delay), time.Duration(lb.delay))
	}
	for _, w := range []*wire{ab, ba} {
		w.mu.Lock()
		w.delay = time.Second
		w.mu.Unlock()
	}
	traffic := func() {
		if !la.closed() {
			data(la)
		}
		if !lb.closed() {
			data(lb)
		}
	}
	h.run(30*time.Second, traffic)
	if la.closed() || lb.closed() {
		t.Fatal("the shaped link closed while its frames came 1 s late")
	}
	for _, w := range []*wire{ab, ba} {
		w.mu.Lock()
		w.lost = true
		w.mu.Unlock()
	}
	var atB time.Duration
	got := h.closedAfterAnswer(la, 20*time.Second, func() {
		traffic()
		if atB == 0 && lb.closed() {
			atB = time.Duration(lb.node.now() - lb.lastAnswer.Load())
		}
	})
	near(t, "A closed", got, 5500*time.Millisecond, 4*h.step)
	h.until("B closed", 5*time.Second, lb.closed, nil)
	if atB == 0 {
		atB = time.Duration(lb.node.now() - lb.lastAnswer.Load())
	}
	near(t, "B closed", atB, 5500*time.Millisecond, 4*h.step)
}

// A link to an older node keeps the older frames and rule: probes every
// 2 s, each flagging acks, closed 6 s after the last reply. Older nodes
// copy flags back, so their replies never switch the link.
func TestOlderNodeKeepsTheOlderFrames(t *testing.T) {
	h := newHarness(t, nil)
	h.step = 50 * time.Millisecond
	x, y, ab, _ := h.pipe()
	y.respond = olderNode
	la := h.a.addLink(NodeID{9}, x, true, "udp", 0, transport.Shaping{})
	h.until("the link up", time.Second, la.up, nil)
	from := h.elapsed()
	h.run(10*time.Second, func() { data(la) })
	if la.newer() {
		t.Fatal("a copied-back flag switched the link to the newer frames")
	}
	n := 0
	for _, k := range kinds(ab, from) {
		switch {
		case k[0] == kindProbe && k[1] == probeSizeV1:
			n++
		case k[0] == kindPacketV1 && k[1] == headerSizeV1+100:
		default:
			t.Fatalf("wrote kind %d of %d bytes to an older node", k[0], k[1])
		}
	}
	if n < 4 || n > 6 {
		t.Errorf("%d probes in 10 s, want one every 2 s", n)
	}
	ab.mu.Lock()
	for _, r := range ab.written {
		if r.f[0] == kindProbe && r.f[1]&flagReadsAcks == 0 {
			t.Errorf("a probe without the reads-acks flag: %x", r.f)
		}
	}
	ab.lost = true
	ab.mu.Unlock()
	got := h.closedAfterAnswer(la, 10*time.Second, nil)
	near(t, "closed", got, 6*time.Second, 2*h.step)
}

// A far-end probe flagging acks switches the link to the newer frames, and
// the far end's first seq less one, from the probe's token, is acked until
// a newer frame comes.
func TestAProbeFlaggingAcksSwitches(t *testing.T) {
	h := newHarness(t, nil)
	x, y, ab, _ := h.pipe()
	la := h.a.addLink(NodeID{9}, x, true, "udp", 0, transport.Shaping{})
	h.run(h.step, nil)
	if la.newer() {
		t.Fatal("newer before the far end said it reads acks")
	}
	probe := []byte{kindProbe, flagReadsAcks, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4}
	if err := y.WritePacket(probe); err != nil {
		t.Fatal(err)
	}
	h.until("the switch", time.Second, la.newer, nil)
	from := h.elapsed()
	data(la)
	h.run(2*h.step, nil)
	ab.mu.Lock()
	defer ab.mu.Unlock()
	var reply, packet []byte
	for _, r := range ab.written {
		switch {
		case r.at < from:
		case r.f[0] == kindProbeReply:
			reply = r.f
		case r.f[0] == kindPacket:
			packet = r.f
		}
	}
	if len(reply) != probeSize || packet == nil {
		t.Fatalf("after the switch: reply %x, packet %x; want the newer frames", reply, packet)
	}
	if ack := binary.BigEndian.Uint32(packet[headerSizeV1+4:]); ack != 0x12345678 {
		t.Fatalf("acked %#x, want the token's 0x12345678", ack)
	}
}

// A relay writes its own seq and ack on a newer link, and an older node's
// packet with no room for them (the next link refuses it longer) goes on
// as it came.
func TestRelayFallsBackForPacketsWithNoRoom(t *testing.T) {
	h := newHarness(t, nil)
	old := NodeID{9}
	r, n := h.a, h.b
	_, _, rn, _ := h.link("udp", transport.Shaping{})
	r.Update(Table{Routes: []Route{{Destination: n.id, NextHops: []NodeID{n.id}}}})
	x, y, _, _ := h.pipe()
	r.addLink(old, x, false, "udp", -1, transport.Shaping{})
	rn.mu.Lock()
	rn.limit = headerSizeV1 + 1000 + seqAckSize - 1
	rn.mu.Unlock()
	from := h.elapsed()
	for _, size := range []int{500, 1000} {
		if err := y.WritePacket(v1Packet(old, n.id, size)); err != nil {
			t.Fatal(err)
		}
	}
	h.until("both delivered", time.Second, func() bool { return n.counters.unknownPeer.Load() == 2 }, nil)
	var got [][2]int
	for _, k := range kinds(rn, from) {
		if k[0] != kindProbe && k[0] != kindProbeReply {
			got = append(got, k)
		}
	}
	want := [][2]int{{kindPacket, HeaderSize + 500}, {kindPacketV1, headerSizeV1 + 1000}}
	if !slices.Equal(got, want) {
		t.Fatalf("relayed %v, want %v", got, want)
	}
	if c := r.Counters(); c.Forwarded != 2 || c.TooLarge != 0 {
		t.Fatalf("relay counters %+v, want both forwarded", c)
	}
}

// Packets moving to another of the neighbor's links hint that the link
// they came on before went silent: once silent for R, it probes at once
// rather than after its idle wait.
func TestAHintProbesASilentLink(t *testing.T) {
	h := newHarness(t, slowest)
	_, lb1, ab1, _ := h.link("udp", transport.Shaping{})
	_, lb2, _, _ := h.link("udp", transport.Shaping{})
	h.run(time.Second, func() { data(lb1) })
	h.run(1100*time.Millisecond, nil) // silent past R (1 s)
	from := h.elapsed()
	data(lb2)
	h.run(3*h.step, nil)
	if probes(ab1, from) == 0 {
		t.Fatal("the silent link sent no probe when the neighbor's packets came another way")
	}
}
