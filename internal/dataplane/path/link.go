package path

import (
	"context"
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
	id    NodeID
	mu    sync.Mutex
	links []*link
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
}

// pick returns the link to send on: the up link heard from last, or else
// any link, and whether it is up.
func (nb *neighbor) pick(now int64) (*link, bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	var best *link
	var bestRecv int64
	for _, l := range nb.links {
		if r := l.lastRecv.Load(); l.up(now) && r > bestRecv {
			best, bestRecv = l, r
		}
	}
	if best != nil {
		return best, true
	}
	if len(nb.links) > 0 {
		return nb.links[len(nb.links)-1], false
	}
	return nil, false
}

// candidate describes the neighbor as a first hop, from its best link.
func (nb *neighbor) candidate(now int64) Candidate {
	l, up := nb.pick(now)
	c := Candidate{Hop: nb.id, Up: up, Linked: l != nil}
	if l != nil {
		c.RTT = time.Duration(l.rtt.Load())
		if up {
			c.UpFor = time.Duration(now - l.upSince.Load())
		}
	}
	return c
}

// link is one transport link to an adjacent node, with its send queue.
type link struct {
	node   *Node
	nb     *neighbor
	tl     transport.Link
	dialed bool
	queue  chan *[]byte

	done      chan struct{}
	closeOnce sync.Once

	// Monotonic node times in nanoseconds; zero is never.
	created   int64
	lastRecv  atomic.Int64
	lastSent  atomic.Int64
	lastProbe atomic.Int64
	upSince   atomic.Int64
	rtt       atomic.Int64
}

// addLink starts reading and writing tl for nb. An accepted link counts as
// heard from: its listener authenticated it.
func (n *Node) addLink(nb *neighbor, tl transport.Link, dialed bool) *link {
	now := n.now()
	l := &link{
		node: n, nb: nb, tl: tl, dialed: dialed,
		queue: make(chan *[]byte, n.opts.QueueLen),
		done:  make(chan struct{}), created: now,
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

func (l *link) close() {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.tl.Close()
		l.nb.remove(l)
	})
}

// send queues a frame and owns b from then on. A full queue drops it.
func (l *link) send(b *[]byte) bool {
	select {
	case l.queue <- b:
		return true
	default:
		l.node.counters.queueFull.Add(1)
		putBuf(b)
		return false
	}
}

func (l *link) writeLoop() {
	for {
		select {
		case <-l.done:
			return
		case b := <-l.queue:
			err := l.tl.WritePacket(*b)
			putBuf(b)
			switch {
			case err == nil:
				l.lastSent.Store(l.node.now())
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
		*b = (*b)[:n]
		l.node.handle(l, b)
	}
}

// tick closes the link once it has been silent for DeadAfter, and probes a
// dialed link that hasn't both sent and received within ProbeInterval. Only
// the dialing end probes; the other end answers, and hears from the dialer
// at least every ProbeInterval while it is alive.
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

func (l *link) probe(now int64) {
	l.lastProbe.Store(now)
	b := getBuf()
	f := (*b)[:probeSize]
	f[0], f[1] = kindProbe, 0
	binary.BigEndian.PutUint64(f[2:], uint64(now))
	*b = f
	l.send(b)
}

// probeReply measures the round trip of one of this link's probes.
func (l *link) probeReply(f []byte, now int64) {
	sent := int64(binary.BigEndian.Uint64(f[2:]))
	rtt := now - sent
	if !l.dialed || sent <= 0 || rtt < 0 || rtt > int64(l.node.opts.DeadAfter) {
		return
	}
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
// keeps that link until it dies, and starts over. A link that never heard
// back counts as a failed dial: the next attempt tries the next endpoint,
// after a backoff.
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
				l := n.addLink(nb, tl, true)
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
