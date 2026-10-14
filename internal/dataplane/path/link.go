package path

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// neighbor is an adjacent node and its open links: the one this node dials,
// and any it accepted.
type neighbor struct {
	id     NodeID
	mu     sync.Mutex
	links  []*link
	active *link // sticky: traffic stays on it while it is up
}

func (nb *neighbor) all() []*link {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return slices.Clone(nb.links)
}

func (nb *neighbor) add(l *link) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nb.links = append(nb.links, l)
}

func (nb *neighbor) remove(l *link) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	nb.links = slices.DeleteFunc(nb.links, func(x *link) bool { return x == l })
	if nb.active == l {
		nb.active = nil
	}
}

// pick returns the link to send on, and whether it is up: the active link
// while it is up; else the up link proven last, which becomes active; else
// any link.
func (nb *neighbor) pick(now int64) (*link, bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if a := nb.active; a != nil && a.up(now) {
		return a, true
	}
	var best *link
	var bestProof int64
	for _, l := range nb.links {
		if p := l.lastProof.Load(); l.up(now) && p > bestProof {
			best, bestProof = l, p
		}
	}
	if best != nil {
		nb.active = best
		return best, true
	}
	if nb.active != nil {
		return nb.active, false
	}
	if len(nb.links) > 0 {
		return nb.links[len(nb.links)-1], false
	}
	return nil, false
}

// describe fills in c from the link nb sends on.
func (nb *neighbor) describe(c *Candidate, now int64) {
	l, up := nb.pick(now)
	c.Up, c.Linked = up, l != nil
	if l != nil {
		c.RTT = time.Duration(l.rtt.Load())
		if up {
			c.UpFor = time.Duration(now - l.upSince.Load())
		}
	}
}

func (nb *neighbor) status(now int64) []LinkStatus {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	out := make([]LinkStatus, 0, len(nb.links))
	for _, l := range nb.links {
		s := LinkStatus{
			Dialed: l.dialed, Transport: l.transport, Endpoint: l.endpoint, Active: l == nb.active,
			Up: l.up(now), RTT: time.Duration(l.rtt.Load()),
			PacketsIn: l.packetsIn.Load(), PacketsOut: l.packetsOut.Load(),
			BytesIn: l.bytesIn.Load(), BytesOut: l.bytesOut.Load(), QueueFull: l.queueFull.Load(),
		}
		if s.Up {
			s.UpFor = time.Duration(now - l.upSince.Load())
		}
		out = append(out, s)
	}
	return out
}

// maxProbes is how many probes of one link may await a reply; older ones
// are forgotten, and their late replies ignored.
const maxProbes = 8

// link is one transport link to an adjacent node, with its send queue.
type link struct {
	node      *Node
	nb        *neighbor
	tl        transport.Link
	dialed    bool
	transport string
	endpoint  int
	queue     chan *[]byte // packets
	control   chan *[]byte // probes and replies, sent first

	done      chan struct{}
	closeOnce sync.Once

	// Node times in nanoseconds; zero is never. A link is up while a reply
	// to one of its own probes came back within DeadAfter: proof that both
	// directions work.
	created   int64
	lastProof atomic.Int64
	lastProbe atomic.Int64
	lastIn    atomic.Int64
	upSince   atomic.Int64
	rtt       atomic.Int64

	pmu    sync.Mutex
	probes map[uint64]int64 // token → when sent

	packetsIn, packetsOut, bytesIn, bytesOut, queueFull atomic.Uint64
	readFailures, writeFailures                         atomic.Uint64
}

// addLink starts reading and writing tl, a link to the adjacent node id,
// and probes it at once: neither end counts a link as up before a reply.
func (n *Node) addLink(id NodeID, tl transport.Link, dialed bool, transportName string, endpoint int) *link {
	now := n.now()
	l := &link{
		tl: tl, node: n, dialed: dialed, transport: transportName, endpoint: endpoint,
		queue:   make(chan *[]byte, n.opts.QueueLen),
		control: make(chan *[]byte, maxProbes),
		done:    make(chan struct{}), created: now,
		probes: make(map[uint64]int64),
	}
	// Found and joined under one lock, so pruning can't drop the neighbor
	// in between; joined before its goroutines start, so Close (which
	// cancels, then closes every link it finds) can't miss it, and spawning
	// fails once it has cancelled.
	n.nmu.Lock()
	l.nb = n.neighbors[id]
	if l.nb == nil {
		l.nb = &neighbor{id: id}
		n.neighbors[id] = l.nb
	}
	l.nb.add(l)
	n.nmu.Unlock()
	if !n.spawn(l.readLoop) || !n.spawn(l.writeLoop) {
		l.close("the node stopped", nil)
		return l
	}
	l.probe(now)
	return l
}

func (l *link) up(now int64) bool {
	p := l.lastProof.Load()
	return p != 0 && now-p < int64(l.node.opts.DeadAfter)
}

func (l *link) proven(now int64) {
	if !l.up(now) {
		l.upSince.Store(now)
		l.lastProof.Store(now)
		l.node.opts.Log.Info("link up", l.logAttrs(now)...)
		return
	}
	l.lastProof.Store(now)
}

// logAttrs describe the link in logs: whose it is, how it came, what it
// carried. No network address: like Status, logs may leave the device.
func (l *link) logAttrs(now int64) []any {
	attrs := []any{"neighbor", l.nb.id, "transport", l.transport, "dialed", l.dialed}
	if l.dialed {
		attrs = append(attrs, "endpoint", l.endpoint)
	}
	if rtt := l.rtt.Load(); rtt != 0 {
		attrs = append(attrs, "rtt", time.Duration(rtt).Round(time.Millisecond))
	}
	if now == 0 {
		return attrs
	}
	ago := func(t int64) any {
		if t == 0 {
			return "never"
		}
		return time.Duration(now - t).Round(time.Millisecond)
	}
	return append(attrs, "age", time.Duration(now-l.created).Round(time.Millisecond),
		"last_proof", ago(l.lastProof.Load()), "last_in", ago(l.lastIn.Load()),
		"packets_in", l.packetsIn.Load(), "packets_out", l.packetsOut.Load())
}

func (l *link) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// close closes the link for why (err, if any, is what said so) and logs
// it: at info level for a link that was up, at debug for one that never
// was (a dial that went unanswered: its dial loop logs that).
func (l *link) close(why string, err error) {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.tl.Close()
		l.nb.remove(l)
		now := l.node.now()
		attrs := append([]any{"reason", why}, l.logAttrs(now)...)
		if err != nil {
			attrs = append(attrs, "err", err)
		}
		if up := l.upSince.Load(); up != 0 {
			attrs = append(attrs, "was_up_for", time.Duration(now-up).Round(time.Millisecond))
			l.node.opts.Log.Info("link closed", attrs...)
			return
		}
		l.node.opts.Log.Debug("link closed before it came up", attrs...)
	})
}

// failed logs a link's failed read or write: its first at info level, the
// rest at debug.
func (l *link) failed(op string, count *atomic.Uint64, err error) {
	level := slog.LevelDebug
	if count.Add(1) == 1 {
		level = slog.LevelInfo
	}
	l.node.opts.Log.Log(context.Background(), level, "link "+op+" failed", append(l.logAttrs(0), "err", err)...)
}

// send queues a packet frame and owns b from then on. A closed link or a
// full queue drops it.
func (l *link) send(b *[]byte) bool { return l.enqueue(l.queue, b) }

// sendControl queues a probe or a reply ahead of packets, so a busy link
// still proves itself.
func (l *link) sendControl(b *[]byte) bool { return l.enqueue(l.control, b) }

func (l *link) enqueue(q chan *[]byte, b *[]byte) bool {
	if !l.closed() {
		select {
		case q <- b:
			return true
		default:
			l.queueFull.Add(1)
			l.node.counters.queueFull.Add(1)
		}
	}
	putBuf(b)
	return false
}

func (l *link) writeLoop() {
	for {
		var b *[]byte
		select {
		case b = <-l.control:
		default:
			select {
			case <-l.done:
				return
			case b = <-l.control:
			case b = <-l.queue:
			}
		}
		size := len(*b)
		var err error
		if k := (*b)[0]; k == kindProbe || k == kindProbeReply {
			// A transport that shapes may hold these a while; round trips
			// measured with them are upper bounds.
			err = transport.WriteControl(l.tl, *b)
		} else {
			err = l.tl.WritePacket(*b)
		}
		putBuf(b)
		switch {
		case err == nil:
			l.packetsOut.Add(1)
			l.bytesOut.Add(uint64(size))
		case errors.Is(err, net.ErrClosed):
			l.close("the transport closed it", err)
			return
		case errors.Is(err, transport.ErrPacketTooLong) || errors.Is(err, transport.ErrPacketSize):
			l.node.counters.tooLarge.Add(1)
		default:
			l.node.counters.writeFailed.Add(1)
			l.failed("write", &l.writeFailures, err)
		}
	}
}

func (l *link) readLoop() {
	failures := 0
	for {
		b := getBuf()
		n, err := l.tl.ReadPacket(*b)
		if err != nil {
			putBuf(b)
			if errors.Is(err, net.ErrClosed) {
				l.close("the transport closed it", err)
				return
			}
			l.node.counters.readFailed.Add(1)
			l.failed("read", &l.readFailures, err)
			// Any other error loses one packet; don't spin on a run of them.
			if failures++; failures > 3 {
				select {
				case <-l.done:
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
			continue
		}
		failures = 0
		if n == 0 {
			putBuf(b)
			continue
		}
		l.lastIn.Store(l.node.now())
		l.packetsIn.Add(1)
		l.bytesIn.Add(uint64(n))
		*b = (*b)[:n]
		l.node.handle(l, b)
	}
}

// tick closes the link once it has gone DeadAfter without proof that both
// directions work, and probes it when its last proof is older than
// ProbeInterval. Both ends probe: a link that only delivers one way is down
// for both.
func (l *link) tick(now int64) {
	o := l.node.opts
	if now-max(l.lastProof.Load(), l.created) >= int64(o.DeadAfter) {
		l.close("no answer to its probes within "+o.DeadAfter.String(), nil)
		return
	}
	if now-l.lastProbe.Load() >= int64(o.ProbeInterval) && now-l.lastProof.Load() >= int64(o.ProbeInterval) {
		l.probe(now)
	}
}

// probe sends a probe with a random token, remembered until its reply
// comes back or it is one of more than maxProbes waiting.
func (l *link) probe(now int64) {
	var token [8]byte
	_, _ = rand.Read(token[:])
	l.pmu.Lock()
	if len(l.probes) >= maxProbes {
		var oldest uint64
		first := true
		for t, at := range l.probes {
			if first || at < l.probes[oldest] {
				oldest, first = t, false
			}
		}
		delete(l.probes, oldest)
	}
	l.probes[binary.BigEndian.Uint64(token[:])] = now
	l.pmu.Unlock()
	l.lastProbe.Store(now)
	b := getBuf()
	f := (*b)[:probeSize]
	f[0], f[1] = kindProbe, 0
	copy(f[2:], token[:])
	*b = f
	l.sendControl(b)
}

// probeReply proves the link and measures the round trip of one of its
// probes; a reply to no probe it is waiting for is ignored.
func (l *link) probeReply(f []byte, now int64) {
	token := binary.BigEndian.Uint64(f[2:])
	l.pmu.Lock()
	sent, ok := l.probes[token]
	delete(l.probes, token)
	l.pmu.Unlock()
	if !ok {
		return
	}
	l.proven(now)
	rtt := now - sent
	if old := l.rtt.Load(); old != 0 {
		rtt = (7*old + rtt) / 8
	}
	l.rtt.Store(rtt)
}

// dialLoop keeps one dialed link to an adjacent node up.
type dialLoop struct {
	endpoints []Endpoint
	cancel    context.CancelFunc
}

func (d *dialLoop) stop() { d.cancel() }

// startDial dials id's endpoints in priority order until one gives a link,
// keeps that link until it dies, and starts over from the first endpoint.
// A link that was never proven counts as a failed dial: the next attempt
// tries the next endpoint, after a backoff.
func (n *Node) startDial(id NodeID, eps []Endpoint) *dialLoop {
	ctx, cancel := context.WithCancel(n.ctx)
	d := &dialLoop{endpoints: eps, cancel: cancel}
	n.spawn(func() {
		backoff, next, failures := n.opts.RedialMin, 0, 0
		for ctx.Err() == nil {
			ep := eps[next]
			dctx, dcancel := context.WithTimeout(ctx, n.opts.DeadAfter)
			tl, err := ep.Dialer.Dial(dctx, ep.Address, ep.Config)
			dcancel()
			heard := false
			if err == nil {
				l := n.addLink(id, tl, true, ep.Transport, next)
				select {
				case <-l.done:
				case <-ctx.Done():
					l.close("no longer dialed (the table changed, or the node stopped)", nil)
					return
				}
				heard = l.upSince.Load() != 0
				if !heard {
					err = fmt.Errorf("no answer within %v", n.opts.DeadAfter)
				}
			}
			if heard {
				backoff, next, failures = n.opts.RedialMin, 0, 0
			} else {
				if ctx.Err() != nil {
					return
				}
				// The first failure of a run says why at info level; the
				// rest go to debug until a link comes up again.
				level := slog.LevelDebug
				if failures++; failures == 1 {
					level = slog.LevelInfo
				}
				n.opts.Log.Log(ctx, level, "dial failed", "neighbor", id, "transport", ep.Transport, "endpoint", next,
					"failures", failures, "retry_in", backoff, "err", err)
				next = (next + 1) % len(eps)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if !heard {
				backoff = min(2*backoff, n.opts.RedialMax)
			}
		}
	})
	return d
}
