package path

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
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
// while it is up; else the up link heard from last, which becomes active;
// else any link.
func (nb *neighbor) pick(now int64) (*link, bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if a := nb.active; a != nil && a.up(now) {
		return a, true
	}
	var best *link
	var bestRecv int64
	for _, l := range nb.links {
		if r := l.lastRecv.Load(); l.up(now) && r > bestRecv {
			best, bestRecv = l, r
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
	queue     chan *[]byte

	done      chan struct{}
	closeOnce sync.Once

	// Node times in nanoseconds; zero is never.
	created   int64
	lastRecv  atomic.Int64
	lastSent  atomic.Int64
	lastProbe atomic.Int64
	upSince   atomic.Int64
	rtt       atomic.Int64

	pmu    sync.Mutex
	probes map[uint64]int64 // token → when sent

	packetsIn, packetsOut, bytesIn, bytesOut, queueFull atomic.Uint64
}

// addLink starts reading and writing tl for nb. An accepted link counts as
// heard from: its listener authenticated it.
func (n *Node) addLink(nb *neighbor, tl transport.Link, dialed bool, transportName string, endpoint int) *link {
	now := n.now()
	l := &link{
		node: n, nb: nb, tl: tl, dialed: dialed, transport: transportName, endpoint: endpoint,
		queue: make(chan *[]byte, n.opts.QueueLen),
		done:  make(chan struct{}), created: now,
		probes: make(map[uint64]int64),
	}
	if !dialed {
		l.upSince.Store(now)
		l.lastRecv.Store(now)
	}
	// Added before its goroutines start: Close cancels, then closes every
	// link it finds, and spawning fails once it has cancelled.
	nb.add(l)
	if !n.spawn(l.readLoop) || !n.spawn(l.writeLoop) {
		l.close()
	}
	return l
}

func (l *link) up(now int64) bool {
	r := l.lastRecv.Load()
	return r != 0 && now-r < int64(l.node.opts.DeadAfter)
}

func (l *link) received(now int64) {
	if !l.up(now) {
		l.upSince.Store(now)
	}
	l.lastRecv.Store(now)
}

func (l *link) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *link) close() {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.tl.Close()
		l.nb.remove(l)
	})
}

// send queues a frame and owns b from then on. A closed link or a full
// queue drops it.
func (l *link) send(b *[]byte) bool {
	if !l.closed() {
		select {
		case l.queue <- b:
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
		select {
		case <-l.done:
			return
		case b := <-l.queue:
			size := len(*b)
			err := l.tl.WritePacket(*b)
			putBuf(b)
			switch {
			case err == nil:
				l.lastSent.Store(l.node.now())
				l.packetsOut.Add(1)
				l.bytesOut.Add(uint64(size))
			case errors.Is(err, net.ErrClosed):
				l.close()
				return
			}
		}
	}
}

func (l *link) readLoop() {
	defer l.close()
	failures := 0
	for {
		b := getBuf()
		n, err := l.tl.ReadPacket(*b)
		if err != nil {
			putBuf(b)
			if errors.Is(err, net.ErrClosed) {
				return
			}
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
		l.received(l.node.now())
		l.packetsIn.Add(1)
		l.bytesIn.Add(uint64(n))
		*b = (*b)[:n]
		l.node.handle(l, b)
	}
}

// tick closes the link once it has been silent for DeadAfter, and probes a
// dialed link that hasn't both sent and received within ProbeInterval. Only
// the dialing end probes; the other end answers, and hears from the dialer
// at least every ProbeInterval while it is alive. Every frame received
// counts, data as much as probe replies.
func (l *link) tick(now int64) {
	o := l.node.opts
	heard := l.lastRecv.Load()
	if heard == 0 {
		heard = l.created
	}
	if now-heard >= int64(o.DeadAfter) {
		l.close()
		return
	}
	if !l.dialed || now-l.lastProbe.Load() < int64(o.ProbeInterval) {
		return
	}
	if now-l.lastRecv.Load() >= int64(o.ProbeInterval) || now-l.lastSent.Load() >= int64(o.ProbeInterval) {
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
	l.send(b)
}

// probeReply measures the round trip of one of this link's probes; a reply
// to no probe it is waiting for is ignored.
func (l *link) probeReply(f []byte, now int64) {
	token := binary.BigEndian.Uint64(f[2:])
	l.pmu.Lock()
	sent, ok := l.probes[token]
	delete(l.probes, token)
	l.pmu.Unlock()
	if !ok {
		return
	}
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

// startDial dials nb's endpoints in priority order until one gives a link,
// keeps that link until it dies, and starts over from the first endpoint.
// A link that never heard back counts as a failed dial: the next attempt
// tries the next endpoint, after a backoff.
func (n *Node) startDial(nb *neighbor, eps []Endpoint) *dialLoop {
	ctx, cancel := context.WithCancel(n.ctx)
	d := &dialLoop{endpoints: eps, cancel: cancel}
	n.spawn(func() {
		backoff, next := n.opts.RedialMin, 0
		for ctx.Err() == nil {
			ep := eps[next]
			dctx, dcancel := context.WithTimeout(ctx, n.opts.DeadAfter)
			tl, err := ep.Dialer.Dial(dctx, ep.Address, ep.Config)
			dcancel()
			heard := false
			if err == nil {
				l := n.addLink(nb, tl, true, ep.Transport, next)
				l.probe(n.now())
				select {
				case <-l.done:
				case <-ctx.Done():
					l.close()
					return
				}
				heard = l.upSince.Load() != 0
			}
			if heard {
				backoff, next = n.opts.RedialMin, 0
			} else {
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
