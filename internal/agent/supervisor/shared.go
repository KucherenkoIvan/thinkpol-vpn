package supervisor

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Listener is one of the node's public listeners, from the node owner's map
// (guest spaces never open ports). The supervisor listens on it for every
// space it serves, authenticates whatever arrives with the transport's
// Router, and hands it to the worker of the space the credential belongs
// to.
type Listener struct {
	// Transport is the transport's name in the map; it must be a
	// transport.PacketRoutable or a transport.StreamRoutable in
	// Options.Transports.
	Transport string
	// Address is the IP literal and port to listen on.
	Address string
	// Settings is the transport's own settings message for the listener.
	Settings []byte
	// Camouflage gets whatever fails authentication; nil drops it. It must
	// not block for long: a datagram listener reads on only after it
	// returns.
	Camouflage transport.Camouflage
}

// FairShare decides how much of the shared listeners each space may use
// (PRD N7; TP-040 fills it in with per-space token buckets). The supervisor
// asks Allow before it forwards a datagram to a worker or sends a worker's
// reply, and charges what the worker's socket accepted or what went out.
// Both are called from several goroutines and on every datagram, so they
// must be cheap and never block.
type FairShare interface {
	// Allow reports whether space may move n more bytes now.
	Allow(space transport.SpaceID, n int) bool
	// Charge records n bytes space moved.
	Charge(space transport.SpaceID, n int)
}

// ListenerInfo is one public listener as the supervisor sees it.
type ListenerInfo struct {
	ID        uint32
	Transport string
	Address   string
	// Routed counts datagrams or connections that authenticated as one of
	// a served space's links; Unauthenticated those that went to the
	// camouflage.
	Routed, Unauthenticated uint64
	// Rejected lists the peer links the transport's router can't use, e.g.
	// two links (of the same space or of two) sharing a secret: both are
	// dropped rather than one guessed.
	Rejected []transport.PeerError
}

// SharedCounters are what the shared listeners did for one space.
type SharedCounters struct {
	// Forwarded counts the datagrams (ForwardedBytes their bytes) the
	// worker's socket accepted, and Streams the connections handed over.
	Forwarded, ForwardedBytes, Streams uint64
	// NoWorker counts datagrams and connections dropped while the space
	// had no running worker, WorkerFull those its socket had no room for,
	// OverShare those its fair share refused.
	NoWorker, WorkerFull, OverShare uint64
	// Replies counts datagrams (ReplyBytes their bytes) the worker sent
	// out; RepliesRefused those it addressed to a remote end none of its
	// own authenticated datagrams came from lately, or through a listener
	// that is gone, or past its fair share.
	Replies, ReplyBytes, RepliesRefused uint64
}

const (
	// replyWindow is how long a remote end an authenticated datagram came
	// from stays a valid destination for the worker's replies: as long as
	// a datagram stays fresh for the udp transport.
	replyWindow = 5 * time.Minute
	// maxReplyPeers bounds a space's remembered remote ends.
	maxReplyPeers = 1 << 14
	// streamRouteTimeout bounds how long a new connection may take to show
	// the router who it is.
	streamRouteTimeout = 10 * time.Second
	// maxDatagramRead is a public socket's read buffer: anything longer
	// than the transport's largest datagram fails authentication anyway.
	maxDatagramRead = ipc.MaxDatagramSize
)

// workerSockets is a running worker's end of the shared listeners: its data
// socket for datagrams, its control socket for stream handoffs. Both sends
// must not block.
type workerSockets struct {
	data interface {
		TrySendDatagram(ipc.DatagramHeader, []byte) error
	}
	control interface{ TrySend(ipc.Message) error }
}

// shared is the supervisor's shared listeners: the public sockets, the
// spaces' merged credential tables, and a route to each space's current
// worker. No send to a worker blocks, so one stuck worker never holds up
// another space's traffic.
type shared struct {
	reg  *transport.Registry
	fair FairShare
	log  *slog.Logger
	now  func() time.Time

	mu        sync.Mutex // SetSpaces and SetListeners
	nextID    uint32
	listeners map[string]*publicListener // by transport and address
	tables    map[string]*transport.PeerTable
	closed    bool

	// Read on every datagram, so swapped as a whole.
	routes atomic.Pointer[map[transport.SpaceID]*route]
	byID   atomic.Pointer[map[uint32]*publicListener]
}

func newShared(reg *transport.Registry, fair FairShare, log *slog.Logger, now func() time.Time) *shared {
	s := &shared{reg: reg, fair: fair, log: log, now: now, listeners: map[string]*publicListener{}, tables: map[string]*transport.PeerTable{}}
	s.routes.Store(&map[transport.SpaceID]*route{})
	s.byID.Store(&map[uint32]*publicListener{})
	return s
}

// route is one space's way to its current worker, across the worker's
// restarts.
type route struct {
	space    transport.SpaceID
	end      atomic.Pointer[workerSockets] // nil while no worker runs
	counters sharedCounters

	mu    sync.Mutex
	peers map[replyPeer]time.Time // remote ends of the space's authenticated datagrams
}

type replyPeer struct {
	listener uint32
	remote   netip.AddrPort
}

type sharedCounters struct {
	forwarded, forwardedBytes, streams, noWorker, workerFull, overShare,
	replies, replyBytes, repliesRefused atomic.Uint64
}

func (c *sharedCounters) snapshot() SharedCounters {
	return SharedCounters{
		Forwarded: c.forwarded.Load(), ForwardedBytes: c.forwardedBytes.Load(), Streams: c.streams.Load(),
		NoWorker: c.noWorker.Load(), WorkerFull: c.workerFull.Load(), OverShare: c.overShare.Load(),
		Replies: c.replies.Load(), ReplyBytes: c.replyBytes.Load(), RepliesRefused: c.repliesRefused.Load(),
	}
}

// publicListener is one public socket or stream listener.
type publicListener struct {
	id       uint32
	key      string
	cfg      Listener
	settings string
	pc       net.PacketConn // a datagram transport's
	udp      *net.UDPConn   // pc, when it is one: no allocation per datagram
	ln       net.Listener   // a stream transport's
	router   transport.Router
	camo     atomic.Pointer[transport.Camouflage]
	ctx      context.Context // ends when the listener closes
	cancel   context.CancelFunc
	closing  sync.Once
	wg       sync.WaitGroup

	routed, unauthenticated atomic.Uint64
}

func listenerKey(l Listener) string { return l.Transport + " " + l.Address }

// setSpaces makes the merged credential tables and the routes those of
// inbound: per space, the links each transport accepts, from the space's
// own map. Every entry's Space is stamped with the space it is listed
// under, whatever it said.
func (s *shared) setSpaces(inbound map[transport.SpaceID]map[string][]transport.PeerLink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Routes before tables: a link that authenticates has a route.
	old := *s.routes.Load()
	routes := make(map[transport.SpaceID]*route, len(inbound))
	for space := range inbound {
		r := old[space]
		if r == nil {
			r = &route{space: space, peers: map[replyPeer]time.Time{}}
		}
		routes[space] = r
	}
	s.routes.Store(&routes)
	merged := map[string][]transport.PeerLink{}
	for _, space := range slices.SortedFunc(maps.Keys(inbound), func(a, b transport.SpaceID) int { return compareIDs(a[:], b[:]) }) {
		for name, links := range inbound[space] {
			for _, pl := range links {
				pl.Peer.Space = space
				merged[name] = append(merged[name], pl)
			}
		}
	}
	for name, links := range merged {
		s.table(name).Set(links)
	}
	for name, t := range s.tables {
		if _, ok := merged[name]; !ok {
			t.Set(nil)
		}
	}
}

func compareIDs(a, b []byte) int { return slices.Compare(a, b) }

// table is a transport's merged credential table; s.mu held.
func (s *shared) table(name string) *transport.PeerTable {
	t := s.tables[name]
	if t == nil {
		t = transport.NewPeerTable()
		s.tables[name] = t
	}
	return t
}

// setListeners opens, keeps and closes public listeners so the node listens
// on exactly ls. A listener whose transport and address stay keeps its
// socket (and its id); a settings change reopens it. It reports whether
// the set changed, for the workers' Listeners message.
func (s *shared) setListeners(ctx context.Context, ls []Listener) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, errors.New("supervisor: closed")
	}
	want := make(map[string]Listener, len(ls))
	for _, l := range ls {
		k := listenerKey(l)
		if _, dup := want[k]; dup {
			return false, fmt.Errorf("supervisor: listener %s listed twice", k)
		}
		want[k] = l
	}
	changed := false
	for k, pl := range s.listeners {
		if l, ok := want[k]; ok && string(l.Settings) == pl.settings {
			pl.setCamouflage(l.Camouflage)
			continue
		}
		pl.close()
		delete(s.listeners, k)
		changed = true
	}
	var errs []error
	for _, l := range ls {
		k := listenerKey(l)
		if _, ok := s.listeners[k]; ok {
			continue
		}
		pl, err := s.open(ctx, l)
		if err != nil {
			errs = append(errs, fmt.Errorf("supervisor: listener %s: %w", k, err))
			continue
		}
		s.listeners[k] = pl
		changed = true
	}
	byID := make(map[uint32]*publicListener, len(s.listeners))
	for _, pl := range s.listeners {
		byID[pl.id] = pl
	}
	s.byID.Store(&byID)
	return changed, errors.Join(errs...)
}

// open opens one public listener and starts serving it; s.mu held.
func (s *shared) open(ctx context.Context, l Listener) (*publicListener, error) {
	if s.reg == nil {
		return nil, errors.New("no transports")
	}
	t, ok := s.reg.Get(l.Transport)
	if !ok {
		return nil, errors.New("unknown transport")
	}
	s.nextID++
	pl := &publicListener{id: s.nextID, key: listenerKey(l), cfg: l, settings: string(l.Settings)}
	pl.ctx, pl.cancel = context.WithCancel(context.Background())
	pl.setCamouflage(l.Camouflage)
	cfg := transport.ListenConfig{Address: l.Address, Settings: l.Settings}
	switch t := t.(type) {
	case transport.PacketRoutable:
		pc, err := t.ListenPacket(ctx, cfg)
		if err != nil {
			pl.cancel()
			return nil, err
		}
		pl.pc = pc
		pl.udp, _ = pc.(*net.UDPConn)
		pl.router = t.Router(s.table(l.Transport))
		pl.wg.Add(1)
		go s.serveDatagrams(pl)
	case transport.StreamRoutable:
		ln, err := t.ListenStream(ctx, cfg)
		if err != nil {
			pl.cancel()
			return nil, err
		}
		pl.ln = ln
		pl.router = t.Router(s.table(l.Transport))
		pl.wg.Add(1)
		go s.serveStreams(pl)
	default:
		pl.cancel()
		return nil, errors.New("the transport can't sit behind a shared listener")
	}
	return pl, nil
}

func (pl *publicListener) setCamouflage(c transport.Camouflage) {
	c = transport.OrDrop(c)
	pl.camo.Store(&c)
}

func (pl *publicListener) camouflage() transport.Camouflage { return *pl.camo.Load() }

// close stops the listener and waits for its goroutines.
func (pl *publicListener) close() {
	pl.closing.Do(func() {
		pl.cancel()
		if pl.pc != nil {
			_ = pl.pc.Close()
		}
		if pl.ln != nil {
			_ = pl.ln.Close()
		}
	})
	pl.wg.Wait()
}

func (pl *publicListener) closed() bool { return pl.ctx.Err() != nil }

func (pl *publicListener) info() ListenerInfo {
	li := ListenerInfo{
		ID: pl.id, Transport: pl.cfg.Transport, Address: pl.cfg.Address,
		Routed: pl.routed.Load(), Unauthenticated: pl.unauthenticated.Load(),
	}
	if r, ok := pl.router.(interface{ Rejected() []transport.PeerError }); ok {
		li.Rejected = r.Rejected()
	}
	return li
}

// ipcListeners is what the workers are told about the listeners.
func (s *shared) ipcListeners() []ipc.Listener {
	byID := *s.byID.Load()
	out := make([]ipc.Listener, 0, len(byID))
	for _, pl := range byID {
		out = append(out, ipc.Listener{ID: pl.id, Transport: pl.cfg.Transport, Stream: pl.ln != nil, Address: pl.cfg.Address})
	}
	slices.SortFunc(out, func(a, b ipc.Listener) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

func (s *shared) infos() []ListenerInfo {
	byID := *s.byID.Load()
	out := make([]ListenerInfo, 0, len(byID))
	for _, pl := range byID {
		out = append(out, pl.info())
	}
	slices.SortFunc(out, func(a, b ListenerInfo) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

func (s *shared) counters(space transport.SpaceID) SharedCounters {
	if r := (*s.routes.Load())[space]; r != nil {
		return r.counters.snapshot()
	}
	return SharedCounters{}
}

// close closes every public listener; nothing is forwarded after it
// returns.
func (s *shared) close() {
	s.mu.Lock()
	s.closed = true
	ls := slices.Collect(maps.Values(s.listeners))
	clear(s.listeners)
	s.byID.Store(&map[uint32]*publicListener{})
	s.mu.Unlock()
	for _, pl := range ls {
		pl.close()
	}
}

// attach routes space's traffic to a running worker's sockets until the
// returned detach is called. Nothing is routed to a space without a route
// (one not in the latest setSpaces).
func (s *shared) attach(space transport.SpaceID, ws *workerSockets) (detach func()) {
	r := (*s.routes.Load())[space]
	if r == nil {
		// setSpaces runs before a new space's worker starts; a space it
		// dropped is being stopped.
		return func() {}
	}
	r.end.Store(ws)
	return func() { r.end.CompareAndSwap(ws, nil) }
}

// serveDatagrams reads a public datagram socket until it closes.
func (s *shared) serveDatagrams(pl *publicListener) {
	defer pl.wg.Done()
	buf := make([]byte, maxDatagramRead)
	var pause time.Duration
	for {
		n, from, err := pl.read(buf)
		if err != nil {
			if pl.closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			// e.g. an ICMP error surfacing on the socket
			pause = min(max(2*pause, time.Millisecond), 100*time.Millisecond)
			time.Sleep(pause)
			continue
		}
		pause = 0
		d := buf[:n]
		peer, ok := pl.router.RouteDatagram(d)
		var r *route
		if ok {
			r = (*s.routes.Load())[peer.Space]
		}
		if r == nil {
			pl.unauthenticated.Add(1)
			pl.camouflage().Datagram(d, net.UDPAddrFromAddrPort(from))
			continue
		}
		pl.routed.Add(1)
		s.forward(r, pl.id, from, d)
	}
}

func (pl *publicListener) read(buf []byte) (int, netip.AddrPort, error) {
	if pl.udp != nil {
		n, from, err := pl.udp.ReadFromUDPAddrPort(buf)
		return n, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), err
	}
	n, addr, err := pl.pc.ReadFrom(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, netip.AddrPort{}, fmt.Errorf("supervisor: a %T remote address", addr)
	}
	ap := ua.AddrPort()
	return n, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// forward hands one authenticated datagram to r's worker, without blocking,
// and charges r's fair share once the worker's socket took it.
func (s *shared) forward(r *route, listener uint32, from netip.AddrPort, d []byte) {
	ws := r.end.Load()
	if ws == nil {
		r.counters.noWorker.Add(1)
		return
	}
	if s.fair != nil && !s.fair.Allow(r.space, len(d)) {
		r.counters.overShare.Add(1)
		return
	}
	if err := ws.data.TrySendDatagram(ipc.DatagramHeader{Listener: listener, Remote: from}, d); err != nil {
		// ErrFull, or the worker is going away.
		r.counters.workerFull.Add(1)
		return
	}
	r.counters.forwarded.Add(1)
	r.counters.forwardedBytes.Add(uint64(len(d)))
	r.remember(replyPeer{listener, from}, s.now())
	if s.fair != nil {
		s.fair.Charge(r.space, len(d))
	}
}

// remember makes p a valid destination for the space's replies for
// replyWindow.
func (r *route) remember(p replyPeer, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.peers[p]; !ok && len(r.peers) >= maxReplyPeers {
		for k, at := range r.peers {
			if now.Sub(at) > replyWindow {
				delete(r.peers, k)
			}
		}
		if len(r.peers) >= maxReplyPeers {
			return
		}
	}
	r.peers[p] = now
}

func (r *route) mayReplyTo(p replyPeer, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.peers[p]
	if ok && now.Sub(at) > replyWindow {
		delete(r.peers, p)
		return false
	}
	return ok
}

// reply sends a datagram a space's worker wrote out through the public
// socket it names. A worker may only answer: the destination must be a
// remote end one of its space's authenticated datagrams came from, through
// that listener, within replyWindow. So a worker can't use the node's
// public address to reach anyone else, whatever egress its space has.
func (s *shared) reply(space transport.SpaceID, h ipc.DatagramHeader, d []byte) {
	r := (*s.routes.Load())[space]
	if r == nil {
		return
	}
	pl := (*s.byID.Load())[h.Listener]
	if pl == nil || pl.pc == nil || !r.mayReplyTo(replyPeer{h.Listener, h.Remote}, s.now()) ||
		(s.fair != nil && !s.fair.Allow(space, len(d))) {
		r.counters.repliesRefused.Add(1)
		return
	}
	var err error
	if pl.udp != nil {
		_, err = pl.udp.WriteToUDPAddrPort(d, h.Remote)
	} else {
		_, err = pl.pc.WriteTo(d, net.UDPAddrFromAddrPort(h.Remote))
	}
	if err != nil {
		return // lost, as a datagram may be
	}
	r.counters.replies.Add(1)
	r.counters.replyBytes.Add(uint64(len(d)))
	if s.fair != nil {
		s.fair.Charge(space, len(d))
	}
}

// serveStreams accepts connections on a public stream listener until it
// closes; each is routed on its own goroutine, so a slow one holds up no
// other.
func (s *shared) serveStreams(pl *publicListener) {
	defer pl.wg.Done()
	var pause time.Duration
	for {
		conn, err := pl.ln.Accept()
		if err != nil {
			if pl.closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			pause = min(max(2*pause, 5*time.Millisecond), time.Second)
			time.Sleep(pause)
			continue
		}
		pause = 0
		pl.wg.Add(1)
		go func() {
			defer pl.wg.Done()
			s.routeStream(pl, conn)
		}()
	}
}

// routeStream lets the router read the start of conn, then hands conn (its
// descriptor and the bytes the router consumed) to its space's worker, or
// all of it to the camouflage.
func (s *shared) routeStream(pl *publicListener, conn net.Conn) {
	_ = conn.SetReadDeadline(s.now().Add(streamRouteTimeout))
	stop := context.AfterFunc(pl.ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	peer, consumed, ok := pl.router.RouteStream(conn)
	stop()
	_ = conn.SetReadDeadline(time.Time{})
	var r *route
	if ok {
		r = (*s.routes.Load())[peer.Space]
	}
	if r == nil {
		pl.unauthenticated.Add(1)
		pl.camouflage().Stream(conn, consumed)
		return
	}
	pl.routed.Add(1)
	defer func() { _ = conn.Close() }() // the worker has its own descriptor
	ws := r.end.Load()
	if ws == nil {
		r.counters.noWorker.Add(1)
		return
	}
	f, err := fileOf(conn)
	if err != nil {
		s.log.Warn("handing over a connection", "err", err)
		return
	}
	defer func() { _ = f.Close() }()
	if err := ws.control.TrySend(ipc.StreamMessage(pl.id, f, consumed)); err != nil {
		r.counters.workerFull.Add(1)
		return
	}
	r.counters.streams.Add(1)
}

// fileOf duplicates a connection's descriptor for passing to a worker.
func fileOf(conn net.Conn) (*os.File, error) {
	fc, ok := conn.(interface{ File() (*os.File, error) })
	if !ok {
		return nil, fmt.Errorf("a %T has no descriptor to hand over", conn)
	}
	return fc.File()
}
