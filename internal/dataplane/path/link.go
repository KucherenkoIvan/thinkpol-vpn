package path

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// neighbor is an adjacent node and its open links: the one this node dials,
// and any it accepted.
type neighbor struct {
	id      NodeID
	follows bool // this node's id is the higher: it sends where answers come from
	mu      sync.Mutex
	links   []*link
	active  *link // the leader's: traffic stays on it while it is up

	lastRecv atomic.Pointer[link] // the link the neighbor's latest packet came on
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

// pick returns the link to send on, and whether it is up. The leader
// (the lower node id) keeps its active link while it is up; the follower
// sends where its latest answer came from. Else the up link answered last,
// which becomes active; else any link.
func (nb *neighbor) pick() (*link, bool) {
	nb.mu.Lock()
	defer nb.mu.Unlock()
	if a := nb.active; a != nil && a.up() && !nb.follows {
		return a, true
	}
	var best *link
	var bestAnswer int64
	for _, l := range nb.links {
		if p := l.lastAnswer.Load(); l.up() && p > bestAnswer {
			best, bestAnswer = l, p
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
	l, up := nb.pick()
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
			Up: l.up(), RTT: time.Duration(l.rtt.Load()),
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

	// Node times in nanoseconds; zero is never. A link is up once it was
	// answered (liveness.go), until it closes.
	created    int64
	lastAnswer atomic.Int64
	lastIn     atomic.Int64
	upSince    atomic.Int64
	rtt        atomic.Int64 // smoothed probe round trip

	delay int64 // D: both ends' shaping delay
	idle  Range // I's range, the transport's

	lmu   sync.Mutex
	lv    liveness
	timer timer
	armed int64 // the deadline the timer is set for

	pmu    sync.Mutex
	probes map[uint64]int64 // token → when sent

	packetsIn, packetsOut, bytesIn, bytesOut, queueFull atomic.Uint64
	readFailures, writeFailures                         atomic.Uint64

	// For logs: the socket's local port, and the far end's address as
	// last seen (the watcher's alone) with its tag (remoteTag).
	localPort        int
	remote, remoteID string
}

// shapedLink is a link that says how this end shapes it; an accepted link
// that doesn't counts as unshaped.
type shapedLink interface{ Shaping() transport.Shaping }

// addLink starts reading and writing tl, a link to the adjacent node id
// that this end shapes as s, and probes it at once: neither end counts a
// link as up before an answer.
func (n *Node) addLink(id NodeID, tl transport.Link, dialed bool, transportName string, endpoint int, s transport.Shaping) *link {
	now := n.now()
	if sl, ok := tl.(shapedLink); ok && !dialed {
		s = sl.Shaping()
	}
	idle, ok := n.opts.Idle[transportName]
	if !ok {
		idle = n.opts.IdleDefault
	}
	l := &link{
		tl: tl, node: n, dialed: dialed, transport: transportName, endpoint: endpoint,
		queue:   make(chan *[]byte, n.opts.QueueLen),
		control: make(chan *[]byte, maxProbes+1),
		done:    make(chan struct{}), created: now,
		probes:    make(map[uint64]int64),
		localPort: portOf(tl.LocalAddr()),
		// The far end's shaping isn't known here: it is taken to be this
		// end's, as the map sets both ends of a link.
		delay: 2 * int64(s.MaxDelay()),
		idle:  idle,
	}
	l.initLiveness(now)
	l.remote = addrString(tl.RemoteAddr())
	l.remoteID = remoteTag(l.remote)
	// Found and joined under one lock, so pruning can't drop the neighbor
	// in between; joined before its goroutines start, so Close (which
	// cancels, then closes every link it finds) can't miss it, and spawning
	// fails once it has cancelled.
	n.nmu.Lock()
	l.nb = n.neighbors[id]
	if l.nb == nil {
		l.nb = &neighbor{id: id, follows: bytes.Compare(n.id[:], id[:]) > 0}
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

func (l *link) up() bool { return l.upSince.Load() != 0 && !l.closed() }

// logAttrs describe the link in logs: whose it is, how it came, what it
// carried. No network address: like Status, logs may leave the device. The
// local port and the far end's tag tell a NAT rebind or a new socket apart.
func (l *link) logAttrs(now int64) []any {
	attrs := []any{"neighbor", l.nb.id, "transport", l.transport, "dialed", l.dialed, "local_port", l.localPort, "remote", l.remoteID}
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
		"last_answer", ago(l.lastAnswer.Load()), "last_in", ago(l.lastIn.Load()),
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
		l.lmu.Lock()
		if l.timer != nil {
			l.timer.Stop()
		}
		l.lmu.Unlock()
		_ = l.tl.Close()
		l.nb.remove(l)
		now := l.node.now()
		attrs := append([]any{"reason", why}, l.logAttrs(now)...)
		if err != nil {
			attrs = append(attrs, "err", redact(err))
		}
		if up := l.upSince.Load(); up != 0 {
			// From its first answer to its last: not the silence before
			// the close.
			attrs = append(attrs, "proven_for", time.Duration(l.lastAnswer.Load()-up).Round(time.Millisecond))
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
	l.node.opts.Log.Log(context.Background(), level, "link "+op+" failed", append(l.logAttrs(0), "err", redact(err))...)
}

// watchRemote logs the far end's address changing under the link (a NAT
// rebind the listener follows), by its tag. Only the node's watcher calls
// it.
func (l *link) watchRemote() {
	a := addrString(l.tl.RemoteAddr())
	if a == l.remote {
		return
	}
	prev := l.remoteID
	l.remote, l.remoteID = a, remoteTag(a)
	l.node.opts.Log.Info("link remote moved", append(l.logAttrs(0), "previous", prev)...)
}

// processKey keys remoteTag: tags stay comparable within one process, and
// no table of addresses turns them back into addresses.
var processKey = func() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}()

// remoteTag names an address in logs without saying it.
func remoteTag(addr string) string {
	if addr == "" {
		return ""
	}
	m := hmac.New(sha256.New, processKey)
	m.Write([]byte(addr))
	return hex.EncodeToString(m.Sum(nil)[:4])
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func portOf(a net.Addr) int {
	if ap, err := netip.ParseAddrPort(addrString(a)); err == nil {
		return int(ap.Port())
	}
	return 0
}

// addrPattern matches what an error may quote of a network address: IPv4
// with or without a port, bracketed IPv6 with a port, bare IPv6 (with a
// zone), IPv4-mapped IPv6. It errs on matching too much (a clock reading),
// never too little.
var addrPattern = regexp.MustCompile(`\[[0-9A-Za-z:.%_-]+\](:\d+)?|` +
	`(?i)::ffff:\d{1,3}(?:\.\d{1,3}){3}(?:%[0-9A-Za-z_-]+)?|` +
	`\b\d{1,3}(?:\.\d{1,3}){3}(:\d+)?\b|` +
	`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_-]+)?`)

// redact is err's text without network addresses (a *net.OpError quotes
// both ends): logs may leave the device.
func redact(err error) string { return addrPattern.ReplaceAllString(err.Error(), "<addr>") }

// RedactError is err.Error() with network addresses replaced by <addr>.
func RedactError(err error) string {
	if err == nil {
		return ""
	}
	return redact(err)
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
		f := *b
		var err error
		closing := f[0] == kindProbe && f[1]&flagClosing != 0
		control := f[0] == kindProbe || f[0] == kindProbeReply
		if control {
			f, err = l.writeControl(f, closing)
		} else {
			f, err = l.writePacket(f)
		}
		size := len(f)
		putBuf(b)
		switch {
		case err == nil:
			l.packetsOut.Add(1)
			l.bytesOut.Add(uint64(size))
			if control {
				l.node.counters.probesSent.Add(1)
			}
		case errors.Is(err, net.ErrClosed):
			l.close("the transport closed it", err)
			return
		case errors.Is(err, transport.ErrPacketTooLong) || errors.Is(err, transport.ErrPacketSize):
			l.node.counters.tooLarge.Add(1)
		default:
			l.node.counters.writeFailed.Add(1)
			l.failed("write", &l.writeFailures, err)
		}
		if closing {
			l.close(l.closeWhy(), nil)
			return
		}
	}
}

// stamp gives f, a newer-format frame, the next seq and the latest ack at
// off, and returns the seq. Only the writer stamps, under lmu.
func (l *link) stampLocked(f []byte, off int) uint32 {
	lv := &l.lv
	lv.latest++
	binary.BigEndian.PutUint32(f[off:], lv.latest)
	binary.BigEndian.PutUint32(f[off+4:], lv.recv)
	return lv.latest
}

// written settles a stamped frame the transport took (err nil) or refused:
// a refused one never happened; one that expects an answer, written at w,
// meets the busy rules.
func (l *link) written(seq uint32, w int64, expects bool, err error) {
	l.lmu.Lock()
	defer l.lmu.Unlock()
	if err != nil {
		if l.lv.latest == seq {
			l.lv.latest--
		}
		return
	}
	if expects {
		l.wroteLocked(w)
		l.armLocked(w)
	}
}

// writeControl writes a probe, reply or close notice (probeSize bytes as
// queued) in the format the link writes, and returns what it wrote.
func (l *link) writeControl(f []byte, closing bool) ([]byte, error) {
	l.lmu.Lock()
	if !l.lv.newer {
		l.lmu.Unlock()
		f = f[:probeSizeV1]
		// A transport that shapes may hold these a while; round trips
		// measured with them are upper bounds.
		return f, transport.WriteControl(l.tl, f)
	}
	seq := l.stampLocked(f, probeSizeV1)
	l.lmu.Unlock()
	w := l.node.now()
	err := transport.WriteControl(l.tl, f)
	l.written(seq, w, f[0] == kindProbe && !closing, err)
	return f, err
}

// writePacket writes a packet frame of either format in the format the
// link writes, and returns what it wrote. An older packet with no room
// for seq and ack (it already fills a buffer, or the transport refuses it
// longer) goes as it came, neither counting nor answering.
func (l *link) writePacket(f []byte) ([]byte, error) {
	l.lmu.Lock()
	if !l.lv.newer {
		l.lmu.Unlock()
		if f[0] == kindPacket {
			f = toV1(f)
		}
		return f, l.tl.WritePacket(f)
	}
	upgraded := f[0] == kindPacketV1
	if upgraded {
		if len(f)+seqAckSize > cap(f) {
			l.lmu.Unlock()
			return f, l.tl.WritePacket(f)
		}
		f = fromV1(f)
	}
	seq := l.stampLocked(f, headerSizeV1)
	l.lmu.Unlock()
	w := l.node.now()
	err := l.tl.WritePacket(f)
	if upgraded && errors.Is(err, transport.ErrPacketTooLong) {
		l.written(seq, w, false, err)
		f = toV1(f)
		return f, l.tl.WritePacket(f)
	}
	l.written(seq, w, len(f)-HeaderSize != keepaliveSize, err)
	return f, err
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

// probe sends a probe with a random token, remembered until its reply
// comes back or it is one of more than maxProbes waiting. An older-format
// probe's token starts with the link's first seq less one (frame.go).
func (l *link) probe(now int64) {
	var token [8]byte
	_, _ = rand.Read(token[:])
	l.lmu.Lock()
	if !l.lv.newer {
		binary.BigEndian.PutUint32(token[:4], l.lv.first-1)
	}
	l.lv.lastProbe = now
	l.armLocked(now)
	l.lmu.Unlock()
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
	b := getBuf()
	f := (*b)[:probeSize]
	clear(f)
	f[0], f[1] = kindProbe, flagReadsAcks
	copy(f[2:], token[:])
	*b = f
	l.sendControl(b)
}

// awaited takes the token of a probe reply and returns when that probe was
// sent, or 0 for a reply to no probe the link is waiting for.
func (l *link) awaited(f []byte) int64 {
	token := binary.BigEndian.Uint64(f[2:])
	l.pmu.Lock()
	defer l.pmu.Unlock()
	sent, ok := l.probes[token]
	if !ok {
		return 0
	}
	delete(l.probes, token)
	return sent
}

// dialLoop keeps one dialed link to an adjacent node up.
type dialLoop struct {
	endpoints []Endpoint
	cancel    context.CancelFunc
	started   int64       // n.now() when the loop started
	failed    atomic.Bool // a dial attempt has failed since started
}

func (d *dialLoop) stop() { d.cancel() }

// startDial dials id's endpoints in priority order until one gives a link,
// keeps that link until it dies, and starts over from the first endpoint.
// A link that was never proven counts as a failed dial: the next attempt
// tries the next endpoint, after a backoff.
func (n *Node) startDial(id NodeID, eps []Endpoint) *dialLoop {
	ctx, cancel := context.WithCancel(n.ctx)
	d := &dialLoop{endpoints: eps, cancel: cancel, started: n.now()}
	n.spawn(func() {
		backoff, next, failures := n.opts.RedialMin, 0, 0
		for ctx.Err() == nil {
			ep := eps[next]
			dctx, dcancel := context.WithTimeout(ctx, n.opts.DialTimeout)
			tl, err := ep.Dialer.Dial(dctx, ep.Address, ep.Config)
			dcancel()
			heard := false
			if err == nil {
				l := n.addLink(id, tl, true, ep.Transport, next, ep.Config.Shaping)
				select {
				case <-l.done:
				case <-ctx.Done():
					l.close("no longer dialed (the table changed, or the node stopped)", nil)
					return
				}
				heard = l.upSince.Load() != 0
				if !heard {
					err = fmt.Errorf("no answer within %v", n.opts.DialTimeout)
				}
			}
			if heard {
				backoff, next, failures = n.opts.RedialMin, 0, 0
			} else {
				if ctx.Err() != nil {
					return
				}
				d.failed.Store(true)
				// The first failure of a run says why at info level; the
				// rest go to debug until a link comes up again.
				level := slog.LevelDebug
				if failures++; failures == 1 {
					level = slog.LevelInfo
				}
				n.opts.Log.Log(ctx, level, "dial failed", "neighbor", id, "transport", ep.Transport, "endpoint", next,
					"failures", failures, "retry_in", backoff, "err", redact(err))
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
