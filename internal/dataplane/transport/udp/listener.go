package udp

import (
	"context"
	"errors"
	"fmt"
	"io"
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
// datagram that fails authentication; those go to the camouflage.
type Listener struct {
	pc    net.PacketConn
	peers transport.Peers
	camo  transport.Camouflage

	accept    chan *serverLink
	done      chan struct{}
	closeOnce sync.Once

	mu      sync.Mutex
	flows   map[ConnID]*flow
	scratch []byte // packets are opened here, so camouflage sees datagrams intact
}

// flow is the listener's state for one credential. Its replay windows
// outlive the credential's links, so closing a link doesn't reopen the
// window to replays.
type flow struct {
	entry   *peerEntry
	link    *serverLink // nil until a datagram opens one
	senders senderWindows
}

// Listen opens a udp socket on address ("host:port") and listens on it.
// A nil camouflage drops everything unauthenticated.
func Listen(address string, peers transport.Peers, camouflage transport.Camouflage) (*Listener, error) {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, fmt.Errorf("udp: listen: %w", err)
	}
	return NewListener(pc, peers, camouflage), nil
}

// NewListener listens on pc, which it owns from now on. pc need not be a
// socket: a worker behind a shared listener reads the datagrams the
// supervisor routed to it (see Demux) and writes replies back the same way.
func NewListener(pc net.PacketConn, peers transport.Peers, camouflage transport.Camouflage) *Listener {
	l := &Listener{
		pc:      pc,
		peers:   peers,
		camo:    transport.OrDrop(camouflage),
		accept:  make(chan *serverLink, acceptQueue),
		done:    make(chan struct{}),
		flows:   make(map[ConnID]*flow),
		scratch: make([]byte, 0, innerSize+transport.MaxPacketSize),
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

// reindex swaps in a new peer table and closes the links of credentials
// that left it.
func (l *Listener) reindex(links []transport.PeerLink) {
	index := indexPeers(links)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, f := range l.flows {
		if !f.entry.sameAs(index[id]) {
			if f.link != nil {
				f.link.shut(transport.ErrRevoked)
			}
			delete(l.flows, id)
		}
	}
	for id, e := range index {
		if _, ok := l.flows[id]; !ok {
			l.flows[id] = &flow{entry: e}
		}
	}
}

func (l *Listener) readLoop() {
	buf := make([]byte, maxDatagram+1)
	for {
		n, from, err := l.pc.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if !l.closed() && !errors.Is(err, net.ErrClosed) && errors.As(err, &netErr) {
				continue // transient, e.g. an ICMP error surfacing on the socket
			}
			// Closed, or a PacketConn that isn't a socket gave up (io.EOF).
			_ = l.Close()
			return
		}
		if !l.receive(buf[:n], from) {
			l.camo.Datagram(buf[:n], from)
		}
	}
}

// receive delivers an authenticated, fresh datagram to its credential's
// link, opening the link if there is none, and reports whether it did.
func (l *Listener) receive(d []byte, from net.Addr) bool {
	id, ok := connIDOf(d)
	if !ok {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.flows[id]
	if f == nil || l.closed() {
		return false
	}
	sender, counter, packet, err := open(l.scratch[:0], f.entry.recv, d)
	if err != nil {
		return false
	}
	fresh, newest := f.senders.accept(sender, counter)
	if !fresh {
		return false
	}
	if f.link == nil {
		link := newServerLink(l, f, from)
		select {
		case l.accept <- link:
			f.link = link
		default:
			return true // nobody is accepting: dropped, as the network would
		}
	} else if newest {
		// Follows a dialer that moved (NAT rebinding, redial). Only the
		// newest counter of a sender moves it; an on-path attacker can still
		// race a captured datagram ahead of the original, as with WireGuard's
		// own roaming.
		f.link.remote.Store(&from)
	}
	f.link.deliver(packet)
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
		l: l, flow: f, peer: f.entry.link.Peer, sender: newSenderID(),
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
	c := sl.counter.Add(1) - 1
	if c >= rejectAfterMessages {
		return transport.ClosedError(errors.New("udp: counter exhausted"))
	}
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	*bp = seal((*bp)[:0], sl.flow.entry.send, sl.flow.entry.outID, sl.sender, c, p)
	if _, err := sl.l.pc.WriteTo(*bp, *sl.remote.Load()); err != nil {
		select {
		case <-sl.done:
			return sl.closeErr
		default:
		}
		return fmt.Errorf("udp: write: %w", err)
	}
	return nil
}

// Close closes this link only. If the dialer keeps sending, its datagrams
// open a new link.
func (sl *serverLink) Close() error {
	sl.l.mu.Lock()
	if sl.flow.link == sl {
		sl.flow.link = nil
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
