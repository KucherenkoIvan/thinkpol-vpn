package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	acceptQueue = 64
	linkQueue   = 256
)

// Listener accepts udp links on one packet socket. It never answers a
// datagram that fails authentication; those go to the camouflage. The
// accept inbox is the listener's lifecycle: it closes first, so a closing
// listener never hands out a link from Accept.
type Listener struct {
	t     *Transport
	pc    net.PacketConn
	peers transport.Peers
	camo  transport.Camouflage

	accept *transport.Inbox[*serverLink]
	admitLadder
	meter transport.SendMeter

	mu      sync.Mutex
	set     *peerSet
	table   *senderHistories
	flows   map[string]*flow // by secret
	scratch []byte           // packets are opened here, so camouflage sees datagrams intact
}

// flow is the listener's state for one credential's link. The credential's
// sender history is the listener table's, not the flow's, so it outlives
// the link and a settings change doesn't reopen the replay filter.
type flow struct {
	entry atomic.Pointer[peerEntry]
	link  *serverLink // nil until a datagram opens one
}

func newListener(t *Transport, pc net.PacketConn, peers transport.Peers, camouflage transport.Camouflage) *Listener {
	l := &Listener{
		t:       t,
		pc:      pc,
		peers:   peers,
		camo:    transport.OrDrop(camouflage),
		accept:  transport.NewInbox[*serverLink](acceptQueue),
		table:   newSenderHistories(),
		flows:   make(map[string]*flow),
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
	sl, err := l.accept.Recv(ctx)
	if err != nil {
		return nil, transport.Identity{}, err
	}
	return sl, sl.peer, nil
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

// Close implements transport.Listener. The accept inbox closes first, so
// Accept hands out no link of a closing listener. Dialers' links outlive
// it: they carry on with a listener restarted on the same address.
func (l *Listener) Close() error {
	if !l.accept.Close(nil) {
		return nil
	}
	err := l.pc.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range l.flows {
		if f.link != nil {
			f.link.Inbox.Close(nil)
			f.link = nil
		}
	}
	return err
}

func (l *Listener) watchPeers(changed <-chan struct{}) {
	for {
		select {
		case <-l.accept.Done():
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
	l.table.follow(set, now)
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
			f.link.Inbox.Close(reason)
		}
		delete(l.flows, key)
	}
	for key, e := range set.bySecret {
		if _, ok := l.flows[key]; ok {
			continue
		}
		f := &flow{}
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
			if !l.accept.Closed() && !errors.Is(err, net.ErrClosed) && errors.As(err, &netErr) {
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
	now := l.t.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.accept.Closed() {
		return false
	}
	e, o, v := l.admit(l.scratch[:0], l.set, l.table, d, now)
	if v < deliver {
		return false
	}
	f := l.flows[string(e.link.Verifier)]
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
		// Only the current sender's newest counter opens a link, the same
		// rule that moves an open one: a reordered or replayed datagram
		// opens nothing toward the port it came from, however it got
		// there, while a dialer whose link the app closed keeps sending
		// newest counters and opens one at once.
		if v != deliverNewest {
			l.counters.noLink.Add(1)
			return false
		}
		link := newServerLink(l, f, from)
		if !l.accept.TrySend(link) {
			return true // nobody is accepting: dropped, as the network would
		}
		f.link = link
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

	Inbox *transport.Inbox[[]byte]
}

func newServerLink(l *Listener, f *flow, from net.Addr) *serverLink {
	sl := &serverLink{
		l: l, flow: f, peer: f.entry.Load().link.Peer, sender: newSenderID(l.t.now()),
		Inbox: transport.NewInbox[[]byte](linkQueue),
	}
	sl.remote.Store(&from)
	return sl
}

// deliver queues a copy of a packet that lives in the listener's scratch.
func (sl *serverLink) deliver(packet []byte) {
	sl.Inbox.TrySend(append([]byte(nil), packet...))
}

// ReadPacket implements transport.Link: the packets the listener queued.
func (sl *serverLink) ReadPacket(p []byte) (int, error) {
	return transport.ReadPacketFrom(sl.Inbox, p)
}

// WritePacket implements transport.Link.
func (sl *serverLink) WritePacket(p []byte) error {
	if err := transport.CheckPacketSize(p); err != nil {
		return err
	}
	select {
	case <-sl.Inbox.Done():
		return sl.Inbox.Err()
	default:
	}
	e := sl.flow.entry.Load()
	now := sl.l.t.now()
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	*bp = seal((*bp)[:0], e.send, e.out.at(epochOf(now)), sl.sender, now, sl.counter.Add(1)-1, p, e.link.Shaping.Padding)
	if _, err := sl.l.pc.WriteTo(*bp, *sl.remote.Load()); err != nil {
		select {
		case <-sl.Inbox.Done():
			return sl.Inbox.Err()
		default:
		}
		return writeError(err)
	}
	sl.l.meter.Sent(1, len(p), len(*bp)-Overhead-len(p), len(*bp))
	return nil
}

// Close closes this link only. The dialer's next datagram — its newest
// counter — opens a new link; a reordered older one opens nothing.
func (sl *serverLink) Close() error {
	sl.l.mu.Lock()
	if sl.flow.link == sl {
		sl.flow.link = nil
	}
	sl.l.mu.Unlock()
	sl.Inbox.Close(nil)
	return nil
}

func (sl *serverLink) LocalAddr() net.Addr  { return sl.l.pc.LocalAddr() }
func (sl *serverLink) RemoteAddr() net.Addr { return *sl.remote.Load() }
