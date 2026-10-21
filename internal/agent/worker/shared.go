package worker

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// SharedListener is one of the supervisor's public listeners, as this
// worker is served by it: the datagrams or connections the supervisor
// authenticated as this space's.
type SharedListener struct {
	// ID tags what the supervisor forwards; never reused for another
	// listener.
	ID uint32
	// Transport is the transport's name in the map; Stream is set for a
	// stream transport.
	Transport string
	Stream    bool
	// Address is the public address the supervisor listens on.
	Address string
	// Done is closed when the supervisor no longer has the listener.
	Done <-chan struct{}

	packets *forwardedConn // a datagram transport's
	streams chan Stream    // a stream transport's
}

// Listen is the transport's listener for what the supervisor forwards on
// this listener: the worker's counterpart of Transport.Listen, so the data
// plane serves it like any other listener. Listen once per listener: the
// listener ends when the supervisor drops it (Done) and closing it is
// final.
func (l SharedListener) Listen(reg *transport.Registry, accept transport.Accept) (transport.Listener, error) {
	t, ok := reg.Get(l.Transport)
	if !ok {
		return nil, fmt.Errorf("worker: shared listener %d: unknown transport %q", l.ID, l.Transport)
	}
	if !l.Stream {
		pt, ok := t.(transport.PacketRoutable)
		if !ok {
			return nil, fmt.Errorf("worker: shared listener %d: %s isn't a datagram transport behind a shared listener", l.ID, l.Transport)
		}
		return pt.ListenForwarded(l.packets, accept)
	}
	st, ok := t.(transport.StreamRoutable)
	if !ok {
		return nil, fmt.Errorf("worker: shared listener %d: %s isn't a stream transport behind a shared listener", l.ID, l.Transport)
	}
	hl, err := st.Handoff(accept)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			select {
			case <-l.Done:
				_ = hl.Close()
				return
			case s := <-l.streams:
				hl.ServeStream(s.Conn, s.Consumed)
			}
		}
	}()
	return hl, nil
}

// SharedDrops are what the worker dropped of what the supervisor forwarded.
type SharedDrops struct {
	// QueueFull counts datagrams and connections dropped because the
	// listener's reader fell behind.
	QueueFull uint64
	// UnknownListener counts those for a listener the worker doesn't have
	// (any more), or of the wrong kind.
	UnknownListener uint64
}

// Stream is a connection the supervisor routed to this worker, with the
// bytes its router already read from it.
type Stream struct {
	Conn     net.Conn
	Consumed []byte
}

const (
	// forwardedQueue bounds the datagrams waiting for a shared listener's
	// reader; more are dropped, as the network would.
	forwardedQueue = 1024
	// streamQueue bounds the connections waiting to be taken.
	streamQueue = 64
)

// replySender is the worker's data socket, as its listeners write to it.
type replySender interface {
	SendDatagram(ipc.DatagramHeader, []byte) error
}

// sharedListeners is the worker's side of the shared listeners: it keeps
// one entry per listener the supervisor announced, and dispatches what the
// supervisor forwards to it.
type sharedListeners struct {
	send replySender

	queueFull, unknownListener atomic.Uint64

	mu   sync.Mutex
	byID atomic.Pointer[map[uint32]*sharedEntry]
}

type sharedEntry struct {
	l       SharedListener
	packets *forwardedConn
	streams chan Stream
	done    chan struct{}
	closing sync.Once
}

func newSharedListeners(send replySender) *sharedListeners {
	s := &sharedListeners{send: send}
	s.byID.Store(&map[uint32]*sharedEntry{})
	return s
}

// update makes the set ls, keeping the entries of listeners that stay (the
// supervisor never reuses an id), and returns it.
func (s *sharedListeners) update(ls []ipc.Listener) []SharedListener {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := *s.byID.Load()
	next := make(map[uint32]*sharedEntry, len(ls))
	out := make([]SharedListener, 0, len(ls))
	for _, l := range ls {
		e := old[l.ID]
		if e == nil {
			e = newSharedEntry(l, s.send, &s.queueFull)
		}
		next[l.ID] = e
		out = append(out, e.l)
	}
	s.byID.Store(&next)
	for id, e := range old {
		if next[id] == nil {
			e.close()
		}
	}
	return out
}

func newSharedEntry(l ipc.Listener, send replySender, queueFull *atomic.Uint64) *sharedEntry {
	e := &sharedEntry{done: make(chan struct{})}
	e.l = SharedListener{ID: l.ID, Transport: l.Transport, Stream: l.Stream, Address: l.Address, Done: e.done}
	if l.Stream {
		e.streams = make(chan Stream, streamQueue)
		e.l.streams = e.streams
	} else {
		e.packets = newForwardedConn(l, send, e.done, queueFull)
		e.l.packets = e.packets
	}
	return e
}

func (s *sharedListeners) drops() SharedDrops {
	return SharedDrops{QueueFull: s.queueFull.Load(), UnknownListener: s.unknownListener.Load()}
}

func (e *sharedEntry) close() {
	e.closing.Do(func() { close(e.done) })
}

// datagram dispatches one Datagram message's payload from the data socket.
func (s *sharedListeners) datagram(payload []byte) error {
	h, d, err := ipc.ParseDatagram(payload)
	if err != nil {
		return err
	}
	if e := (*s.byID.Load())[h.Listener]; e != nil && e.packets != nil {
		e.packets.deliver(h.Remote, d)
	} else {
		s.unknownListener.Add(1)
	}
	return nil
}

// stream takes over a connection the supervisor handed over; it is closed
// if nobody can take it.
func (s *sharedListeners) stream(listener uint32, conn net.Conn, consumed []byte) {
	e := (*s.byID.Load())[listener]
	if e == nil || e.streams == nil {
		s.unknownListener.Add(1)
		_ = conn.Close()
		return
	}
	select {
	case <-e.done:
		s.unknownListener.Add(1)
		_ = conn.Close()
	case e.streams <- Stream{Conn: conn, Consumed: consumed}:
	default:
		s.queueFull.Add(1)
		_ = conn.Close()
	}
}

// forwardedConn is a worker's view of one public datagram socket: it reads
// what the supervisor forwarded and sends replies back to it, to go out
// through the public socket.
type forwardedConn struct {
	id    uint32
	local net.Addr
	send  replySender
	in    chan forwarded
	done  <-chan struct{} // the listener went
	// closed is closed by Close.
	closed    chan struct{}
	closeOnce sync.Once
	// dropped counts datagrams dropped because the reader fell behind.
	dropped *atomic.Uint64
}

type forwarded struct {
	from netip.AddrPort
	d    []byte
}

var errDeadline = errors.New("worker: a forwarded socket has no deadlines")

func newForwardedConn(l ipc.Listener, send replySender, done <-chan struct{}, dropped *atomic.Uint64) *forwardedConn {
	var local net.Addr = &net.UDPAddr{}
	if ap, err := netip.ParseAddrPort(l.Address); err == nil {
		local = net.UDPAddrFromAddrPort(ap)
	}
	return &forwardedConn{id: l.ID, local: local, send: send, in: make(chan forwarded, forwardedQueue), done: done, closed: make(chan struct{}), dropped: dropped}
}

// deliver queues a datagram; d is the conn's from now on.
func (fc *forwardedConn) deliver(from netip.AddrPort, d []byte) {
	if fc.isClosed() {
		return
	}
	select {
	case fc.in <- forwarded{from, d}:
	default:
		fc.dropped.Add(1)
	}
}

func (fc *forwardedConn) isClosed() bool {
	select {
	case <-fc.done:
		return true
	case <-fc.closed:
		return true
	default:
		return false
	}
}

func (fc *forwardedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if fc.isClosed() {
		return 0, nil, net.ErrClosed
	}
	select {
	case <-fc.done:
		return 0, nil, net.ErrClosed
	case <-fc.closed:
		return 0, nil, net.ErrClosed
	case f := <-fc.in:
		return copy(p, f.d), net.UDPAddrFromAddrPort(f.from), nil
	}
}

func (fc *forwardedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if fc.isClosed() {
		return 0, net.ErrClosed
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("worker: can't send to a %T", addr)
	}
	if err := fc.send.SendDatagram(ipc.DatagramHeader{Listener: fc.id, Remote: ua.AddrPort()}, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends reads and writes for good; what the supervisor forwards to the
// listener from then on is dropped.
func (fc *forwardedConn) Close() error {
	fc.closeOnce.Do(func() { close(fc.closed) })
	return nil
}

func (fc *forwardedConn) LocalAddr() net.Addr                { return fc.local }
func (fc *forwardedConn) SetDeadline(t time.Time) error      { return deadline(t) }
func (fc *forwardedConn) SetReadDeadline(t time.Time) error  { return deadline(t) }
func (fc *forwardedConn) SetWriteDeadline(t time.Time) error { return deadline(t) }

func deadline(t time.Time) error {
	if t.IsZero() {
		return nil
	}
	return errDeadline
}
