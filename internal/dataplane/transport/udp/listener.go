package udp

import (
	"context"
	"crypto/cipher"
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

// flow is the listener's state for one credential. It outlives the links of
// that credential, so a replayed old session can't come back once a newer
// one was seen.
type flow struct {
	entry *peerEntry
	link  *serverLink // the current session's link, nil if none
	epoch uint64      // newest session epoch accepted
	seen  time.Time   // last datagram accepted in that session
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
		scratch: make([]byte, 0, maxDatagram),
	}
	links, changed := peers.Snapshot()
	l.reindex(links)
	go l.watchPeers(changed)
	go l.readLoop()
	return l
}

// Accept implements transport.Listener. A link is accepted when the first
// datagram of its session arrives.
func (l *Listener) Accept(ctx context.Context) (transport.Link, transport.Identity, error) {
	select {
	case <-l.done:
		return nil, transport.Identity{}, transport.ClosedError(nil)
	default:
	}
	select {
	case <-l.done:
		return nil, transport.Identity{}, transport.ClosedError(nil)
	case <-ctx.Done():
		return nil, transport.Identity{}, ctx.Err()
	case sl := <-l.accept:
		return sl, sl.peer, nil
	}
}

// Addr implements transport.Listener.
func (l *Listener) Addr() net.Addr { return l.pc.LocalAddr() }

// Close implements transport.Listener.
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
		if e := index[id]; !f.entry.sameAs(e) {
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

// receive delivers an authenticated, fresh datagram to its link and reports
// whether it did.
func (l *Listener) receive(d []byte, from net.Addr) bool {
	h, ok := parseHeader(d)
	if !ok {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.flows[h.id]
	if f == nil {
		return false
	}
	now := time.Now()
	link := f.link
	if link == nil || link.sess != h.sess {
		if !f.admits(h.sess, now) {
			return false
		}
		recv := f.entry.aead(h.sess, toListener)
		packet, err := open(l.scratch[:0], recv, h, d)
		if err != nil {
			return false
		}
		link = newServerLink(l, f.entry, h.sess, recv, f.entry.aead(h.sess, toDialer), from)
		link.window.accept(h.counter)
		link.deliver(packet)
		select {
		case l.accept <- link:
		default:
			return true // nobody is accepting; the dialer will keep trying
		}
		if f.link != nil {
			f.link.shut(transport.ErrSuperseded)
		}
		f.link, f.epoch, f.seen = link, h.sess.epoch(), now
		return true
	}
	packet, err := open(l.scratch[:0], link.recv, h, d)
	if err != nil || !link.window.accept(h.counter) {
		return false
	}
	f.seen = now
	link.remote.Store(&from)
	link.deliver(packet)
	return true
}

// admits reports whether a new session may start: it must be newer than the
// last one, unless that one has gone quiet.
func (f *flow) admits(s session, now time.Time) bool {
	return f.seen.IsZero() || s.epoch() > f.epoch || now.Sub(f.seen) > sessionIdleTimeout
}

// serverLink is the listener's end of one session.
type serverLink struct {
	l     *Listener
	peer  transport.Identity
	inID  ConnID
	outID ConnID
	sess  session
	recv  cipher.AEAD
	send  cipher.AEAD

	window  replayWindow // guarded by l.mu
	counter atomic.Uint64
	remote  atomic.Pointer[net.Addr]

	in        chan []byte
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newServerLink(l *Listener, e *peerEntry, s session, recv, send cipher.AEAD, from net.Addr) *serverLink {
	sl := &serverLink{
		l: l, peer: e.link.Peer, inID: e.inID, outID: e.outID, sess: s, recv: recv, send: send,
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
		return transport.ClosedError(errors.New("udp: session exhausted, redial"))
	}
	bp := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(bp)
	*bp = seal((*bp)[:0], sl.send, header{id: sl.outID, sess: sl.sess, counter: c}, p)
	if _, err := sl.l.pc.WriteTo(*bp, *sl.remote.Load()); err != nil {
		return fmt.Errorf("udp: write: %w", err)
	}
	return nil
}

// Close closes this link only; the dialer's session is dead from then on and
// it has to redial.
func (sl *serverLink) Close() error {
	sl.l.mu.Lock()
	if f := sl.l.flows[sl.inID]; f != nil && f.link == sl {
		f.link = nil
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
