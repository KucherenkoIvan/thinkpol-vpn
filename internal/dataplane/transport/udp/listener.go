package udp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	acceptQueue = 64
	linkQueue   = 256

	// deadRemoteHold is how long a link the app closed keeps its remote
	// from reopening the flow: within it the datagrams still arriving
	// from that port are the late ones, sent before the link closed. A
	// dialer that comes back redials (a new sender) or moves (a new
	// address) sooner than that.
	deadRemoteHold = 30 * time.Second
)

// Listener accepts udp links on one packet socket. It never answers a
// datagram that fails authentication; those go to the camouflage.
type Listener struct {
	t     *Transport
	pc    net.PacketConn
	peers transport.Peers
	camo  transport.Camouflage

	accept    chan *serverLink
	done      chan struct{}
	closeOnce sync.Once
	counters  counters
	meter     transport.SendMeter

	mu      sync.Mutex
	set     *peerSet
	flows   map[string]*flow   // by secret
	retired map[string]retiree // senders of flows gone from the table, by secret
	scratch []byte             // packets are opened here, so camouflage sees datagrams intact
}

// retiree is a removed flow's sender history, kept while a datagram of it
// could still be fresh, so taking a secret out of the table and putting it
// back doesn't reopen it to replays.
type retiree struct {
	senders *senders
}

// flow is the listener's state for one credential. Its senders outlive the
// credential's links and settings changes, so neither reopens the replay
// filter.
type flow struct {
	entry   atomic.Pointer[peerEntry]
	link    *serverLink // nil until a datagram opens one
	senders *senders
	shut    shutLink
}

// shutLink remembers the end of a link the app closed: it gave up on the
// remote (its probes went unanswered), and the datagrams that port had
// already sent, or that a tap replays from it, must not open the next
// link toward it. A link shut because its credential left the table is
// not remembered: the remote may be alive and sending.
type shutLink struct {
	sender senderID // the flow's current sender when the link closed
	remote net.Addr
	at     time.Time
}

func newListener(t *Transport, pc net.PacketConn, peers transport.Peers, camouflage transport.Camouflage) *Listener {
	l := &Listener{
		t:       t,
		pc:      pc,
		peers:   peers,
		camo:    transport.OrDrop(camouflage),
		accept:  make(chan *serverLink, acceptQueue),
		done:    make(chan struct{}),
		flows:   make(map[string]*flow),
		retired: make(map[string]retiree),
		scratch: make([]byte, 0, maxDatagram),
	}
	links, changed := peers.Snapshot()
	l.reindex(links)
	go l.watchPeers(changed)
	go l.readLoop()
	return l
}

// Accept implements transport.Listener. A link is accepted when the first
// datagram of its credential arrives.
func (l *Listener) Accept(ctx context.Context) (transport.Link, transport.Identity, error) {
	if l.closed() {
		return nil, transport.Identity{}, transport.ClosedError(nil)
	}
	select {
	case <-l.done:
	case <-ctx.Done():
		return nil, transport.Identity{}, ctx.Err()
	case sl := <-l.accept:
		if !l.closed() {
			return sl, sl.peer, nil
		}
	}
	return nil, transport.Identity{}, transport.ClosedError(nil)
}

// Addr implements transport.Listener.
func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// Counters reports what the listener dropped and why.
func (l *Listener) Counters() Counters { return l.counters.snapshot() }

// Sent reports what the listener's links sent and what their padding cost.
func (l *Listener) Sent() transport.SendStats { return l.meter.Stats() }

// Rejected lists the peer links of the table the listener can't use.
func (l *Listener) Rejected() []transport.PeerError {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set.problems()
}

// Close implements transport.Listener. Dialers' links outlive it: they
// carry on with a listener restarted on the same address.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.pc.Close()
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, f := range l.flows {
			if f.link != nil {
				f.link.shut(nil)
				f.link = nil
			}
		}
	})
	return err
}

func (l *Listener) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *Listener) watchPeers(changed <-chan struct{}) {
	for {
		select {
		case <-l.done:
			return
		case <-changed:
		}
		var links []transport.PeerLink
		links, changed = l.peers.Snapshot()
		l.reindex(links)
	}
}

// reindex swaps in a new peer table. Links whose secret left it, or now
// names someone else, close; the others pick up their new settings.
func (l *Listener) reindex(links []transport.PeerLink) {
	now := l.t.now()
	set := indexPeers(links, epochOf(now))
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, r := range l.retired {
		if !sentFresh(r.senders.newest, now) {
			delete(l.retired, key)
		}
	}
	for key, f := range l.flows {
		if e := set.bySecret[key]; e != nil && e.link.Peer == f.entry.Load().link.Peer {
			f.entry.Store(e)
			continue
		}
		if f.link != nil {
			reason := transport.ErrRevoked
			if r, ok := set.refused[key]; ok && r.peer == f.entry.Load().link.Peer {
				reason = fmt.Errorf("%w: %w", transport.ErrSettingsRefused, r.err)
			}
			f.link.shut(reason)
		}
		l.retired[key] = retiree{senders: f.senders}
		delete(l.flows, key)
	}
	for key, e := range set.bySecret {
		if _, ok := l.flows[key]; ok {
			continue
		}
		f := &flow{senders: &senders{}}
		if r, ok := l.retired[key]; ok {
			f.senders = r.senders
			delete(l.retired, key)
		}
		f.entry.Store(e)
		l.flows[key] = f
	}
	l.set = set
}

func (l *Listener) readLoop() {
	buf := make([]byte, maxDatagram+1)
	var b backoff
	for {
		n, from, err := l.pc.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if !l.closed() && !errors.Is(err, net.ErrClosed) && errors.As(err, &netErr) {
				b.wait() // e.g. an ICMP error surfacing on the socket
				continue
			}
			// Closed, or a PacketConn that isn't a socket gave up (io.EOF).
			_ = l.Close()
			return
		}
		b.reset()
		if !l.receive(buf[:n], from) {
			l.camo.Datagram(buf[:n], from)
		}
	}
}

// receive delivers an authenticated, fresh datagram to its credential's
// link, opening the link if there is none, and reports whether it did.
func (l *Listener) receive(d []byte, from net.Addr) bool {
	id, ok := idOf(d)
	if !ok {
		l.counters.unauthenticated.Add(1)
		return false
	}
	now := l.t.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed() {
		return false
	}
	e := l.set.lookup(id, epochOf(now))
	if e == nil {
		l.counters.unauthenticated.Add(1)
		return false
	}
	f := l.flows[string(e.link.Verifier)]
	o, err := open(l.scratch[:0], e.recv, d)
	if err != nil {
		l.counters.unauthenticated.Add(1)
		return false
	}
	if !o.fresh(now) {
		l.counters.staleTimestamp.Add(1)
		return false
	}
	v := f.senders.admit(o.sender, o.counter, o.sent, now)
	switch v {
	case dropReplay:
		l.counters.replayed.Add(1)
		return false
	case dropStale:
		l.counters.staleSender.Add(1)
		return false
	}
	if o.packets == 0 {
		// Cover: it keeps a link's address current, as data does, but
		// carries nothing to open one for.
		if f.link != nil && v == deliverNewest {
			f.link.remote.Store(&from)
		}
		l.counters.received(0)
		return true
	}
	if f.link == nil {
		// The app closed the last link on a remote it gave up on: the
		// datagrams still arriving from that port are the late ones it
		// sent before the link closed, and they reopen the link toward
		// a port nobody answers. A redial is a new sender and a moved
		// remote is a different address, so both open.
		if s := f.shut; now.Sub(s.at) <= deadRemoteHold && s.sender == o.sender && s.remote.String() == from.String() {
			return false
		}
		link := newServerLink(l, f, from)
		select {
		case l.accept <- link:
			f.link = link
			f.shut = shutLink{}
		default:
			return true // nobody is accepting: dropped, as the network would
		}
	} else if v == deliverNewest {
		// Only the current sender's newest counter moves the link: an
		// on-path attacker can still race a datagram it holds ahead of the
		// original, as with WireGuard's own roaming.
		f.link.remote.Store(&from)
	}
	for packet, rest := nextFrame(o.frames); packet != nil; packet, rest = nextFrame(rest) {
		f.link.deliver(packet)
	}
	l.counters.received(o.packets)
	return true
}

// serverLink is the listener's end of one credential's link.
type serverLink struct {
	l      *Listener
	flow   *flow
	peer   transport.Identity
	sender senderID

	counter atomic.Uint64
	remote  atomic.Pointer[net.Addr]

	in        chan []byte
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newServerLink(l *Listener, f *flow, from net.Addr) *serverLink {
	sl := &serverLink{
		l: l, flow: f, peer: f.entry.Load().link.Peer, sender: newSenderID(l.t.now()),
		in:   make(chan []byte, linkQueue),
		done: make(chan struct{}),
	}
	sl.remote.Store(&from)
	return sl
}

// deliver queues a copy of a packet that lives in the listener's scratch.
func (sl *serverLink) deliver(packet []byte) {
	select {
	case sl.in <- append([]byte(nil), packet...):
	default: // reader too slow: drop, as the network would
	}
}

func (sl *serverLink) ReadPacket(p []byte) (int, error) {
	select {
	case <-sl.done:
		return 0, sl.closeErr
	default:
	}
	select {
	case <-sl.done:
		return 0, sl.closeErr
	case packet := <-sl.in:
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	}
}

func (sl *serverLink) WritePacket(p []byte) error {
	if err := transport.CheckPacketSize(p); err != nil {
		return err
	}
	select {
	case <-sl.done:
		return sl.closeErr
	default:
	}
	e := sl.flow.entry.Load()
	now := sl.l.t.now()
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	*bp = seal((*bp)[:0], e.send, e.out.at(epochOf(now)), sl.sender, now, sl.counter.Add(1)-1, p, e.link.Shaping.Padding)
	if _, err := sl.l.pc.WriteTo(*bp, *sl.remote.Load()); err != nil {
		select {
		case <-sl.done:
			return sl.closeErr
		default:
		}
		return writeError(err)
	}
	sl.l.meter.Sent(1, len(p), len(*bp)-Overhead-len(p), len(*bp))
	return nil
}

// Close closes this link only. If the dialer keeps sending, its datagrams
// open a new link.
func (sl *serverLink) Close() error {
	sl.l.mu.Lock()
	if sl.flow.link == sl {
		sl.flow.link = nil
		// The link served the flow's current sender; its late datagrams
		// are the ones still in flight from the remote.
		sl.flow.shut = shutLink{sender: sl.flow.senders.current.id, remote: *sl.remote.Load(), at: sl.l.t.now()}
	}
	sl.l.mu.Unlock()
	sl.shut(nil)
	return nil
}

func (sl *serverLink) shut(reason error) {
	sl.closeOnce.Do(func() {
		sl.closeErr = transport.ClosedError(reason)
		close(sl.done)
	})
}

func (sl *serverLink) LocalAddr() net.Addr  { return sl.l.pc.LocalAddr() }
func (sl *serverLink) RemoteAddr() net.Addr { return *sl.remote.Load() }
