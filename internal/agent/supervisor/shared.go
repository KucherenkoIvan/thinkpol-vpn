package supervisor

import (
	"bytes"
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
	// Camouflage gets whatever fails authentication, or is too old or
	// replayed; nil drops it. It must not block for long: a datagram
	// listener reads on only after it returns.
	Camouflage transport.Camouflage
}

// FairShare decides how much of the shared listeners each space may use
// (PRD N7; TP-040 fills it in with per-space token buckets). The supervisor
// asks Allow before it forwards a datagram to a worker or sends a worker's
// reply, and charges what the worker's socket accepted or what went out.
// Both are called from several goroutines and on every datagram, so they
// must be cheap and never block. Handed-over streams never pass through
// here (DESIGN.md "Fair share").
type FairShare interface {
	// Allow reports whether space may move n more bytes now.
	Allow(space transport.SpaceID, n int) bool
	// Charge records n bytes space moved.
	Charge(space transport.SpaceID, n int)
}

// ListenerInfo is one public listener as the node owner sees it. It is the
// node's own business: none of it (the address, the rejected links of
// every space) goes into any space's telemetry.
type ListenerInfo struct {
	ID        uint32
	Transport string
	Address   string
	// Routed counts datagrams or connections that authenticated as a link
	// of a served space; Unauthenticated those that didn't (to the
	// camouflage); NoSpace those that authenticated as a link of a space
	// not served any more (to the camouflage too).
	Routed, Unauthenticated, NoSpace uint64
	// StreamsOverloaded counts connections that arrived while
	// maxRoutingStreams were being routed: they went to the camouflage.
	StreamsOverloaded uint64
	// Rejected lists the peer links the transport's router can't use, e.g.
	// two links (of the same space or of two) sharing a secret: both are
	// dropped rather than one guessed.
	Rejected []transport.PeerError
}

// SharedCounters are what the shared listeners did for one space; the
// supervisor sends them to the space's worker for its telemetry.
type SharedCounters = ipc.SharedCounters

const (
	// replyWindow is how long a remote end a link's live datagram came from
	// stays a destination for the worker's replies. It is refreshed by
	// every authenticated, fresh, non-replayed datagram, so an active link
	// never loses it: WireGuard sends at least every 2 minutes on a live
	// session (rekeys, and keepalives when configured), and the path
	// layer probes each link every 2 s. NAT mappings expire on a similar
	// scale, so an address quiet for longer is likely gone anyway.
	replyWindow = 2 * time.Minute
	// replyPeersPerLink bounds the remote ends one link keeps; a new one
	// evicts that link's oldest, never another link's.
	replyPeersPerLink = 8
	// replySweep is how often, at most, a space's expired remote ends are
	// swept: expiry is exact to within this.
	replySweep = 10 * time.Second
	// streamRouteTimeout bounds how long a new connection may take to show
	// the router who it is.
	streamRouteTimeout = 10 * time.Second
	// maxRoutingStreams bounds the connections one listener routes at
	// once; more go straight to the camouflage.
	maxRoutingStreams = 1024
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

	// routingLimit is maxRoutingStreams, smaller in tests.
	routingLimit int

	mu        sync.Mutex // setSpaces and setListeners
	nextID    uint32
	listeners map[string]*publicListener // by transport and address
	tables    map[string]*transport.PeerTable
	closed    bool

	// Read on every datagram, so swapped as a whole.
	routes atomic.Pointer[map[transport.SpaceID]*route]
	byID   atomic.Pointer[map[uint32]*publicListener]
}

func newShared(reg *transport.Registry, fair FairShare, log *slog.Logger, now func() time.Time) *shared {
	s := &shared{
		reg: reg, fair: fair, log: log, now: now, routingLimit: maxRoutingStreams,
		listeners: map[string]*publicListener{}, tables: map[string]*transport.PeerTable{},
	}
	s.routes.Store(&map[transport.SpaceID]*route{})
	s.byID.Store(&map[uint32]*publicListener{})
	return s
}

// route is one space's way to its current worker, across the worker's
// restarts, and the remote ends the worker may answer.
type route struct {
	space    transport.SpaceID
	end      atomic.Pointer[workerSockets] // nil while no worker runs
	counters counters

	mu      sync.Mutex
	links   map[transport.NodeID]*linkRemotes
	remotes map[replyKey]*remote
	swept   time.Time
}

// replyKey is a remote end as the worker names it: the listener, and the
// address unmapped and without a zone (the IPC header carries neither).
type replyKey struct {
	listener uint32
	addr     netip.AddrPort
}

func keyOf(listener uint32, a netip.AddrPort) replyKey {
	return replyKey{listener, netip.AddrPortFrom(a.Addr().Unmap().WithZone(""), a.Port())}
}

// remote is a remote end some of the space's links came from.
type remote struct {
	holders int            // links holding it
	at      time.Time      // its latest refresh by any of them
	to      netip.AddrPort // as received, zone included: where replies go
}

// linkRemotes are one link's latest remote ends.
type linkRemotes struct {
	n       int
	entries [replyPeersPerLink]struct {
		key replyKey
		at  time.Time
	}
}

type counters struct {
	forwarded, forwardedBytes, streams, stale, replayed, noWorker, workerFull, overShare,
	streamsRefused, replies, replyBytes, repliesNotAllowed, repliesNoListener, repliesOverShare,
	replyErrors, replyPeersEvicted atomic.Uint64
}

func (c *counters) snapshot() SharedCounters {
	return SharedCounters{
		Forwarded: c.forwarded.Load(), ForwardedBytes: c.forwardedBytes.Load(), Streams: c.streams.Load(),
		Stale: c.stale.Load(), Replayed: c.replayed.Load(),
		NoWorker: c.noWorker.Load(), WorkerFull: c.workerFull.Load(), OverShare: c.overShare.Load(),
		StreamsRefused: c.streamsRefused.Load(),
		Replies:        c.replies.Load(), ReplyBytes: c.replyBytes.Load(),
		RepliesNotAllowed: c.repliesNotAllowed.Load(), RepliesNoListener: c.repliesNoListener.Load(),
		RepliesOverShare: c.repliesOverShare.Load(), ReplyErrors: c.replyErrors.Load(),
		ReplyPeersEvicted: c.replyPeersEvicted.Load(),
	}
}

// publicListener is one public socket or stream listener.
type publicListener struct {
	id       uint32
	cfg      Listener
	settings string
	udp      *net.UDPConn // a datagram transport's
	ln       net.Listener // a stream transport's
	router   transport.Router
	camo     atomic.Pointer[transport.Camouflage]
	ctx      context.Context // ends when the listener closes
	cancel   context.CancelFunc
	closing  sync.Once
	wg       sync.WaitGroup
	routing  chan struct{} // a token per stream being routed

	routed, unauthenticated, noSpace, streamsOverloaded atomic.Uint64
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
			r = &route{space: space, links: map[transport.NodeID]*linkRemotes{}, remotes: map[replyKey]*remote{}}
		}
		routes[space] = r
	}
	s.routes.Store(&routes)
	merged := map[string][]transport.PeerLink{}
	for _, space := range slices.SortedFunc(maps.Keys(inbound), func(a, b transport.SpaceID) int { return bytes.Compare(a[:], b[:]) }) {
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
// on exactly ls. A listener whose transport, address and settings stay
// keeps its socket (and its id). One whose settings changed is closed and
// opened again, under a new id: its port is free in between, and lost if
// the reopen fails (reported, the others served). It reports whether the
// set changed, for the workers' Listeners message.
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
	pl := &publicListener{cfg: l, settings: string(l.Settings), routing: make(chan struct{}, s.routingLimit)}
	pl.setCamouflage(l.Camouflage)
	cfg := transport.ListenConfig{Address: l.Address, Settings: l.Settings}
	switch t := t.(type) {
	case transport.PacketRoutable:
		pc, err := t.ListenPacket(ctx, cfg)
		if err != nil {
			return nil, err
		}
		pl.udp = pc
		pl.router = t.Router(s.table(l.Transport))
	case transport.StreamRoutable:
		ln, err := t.ListenStream(ctx, cfg)
		if err != nil {
			return nil, err
		}
		pl.ln = ln
		pl.router = t.Router(s.table(l.Transport))
	default:
		return nil, errors.New("the transport can't sit behind a shared listener")
	}
	s.nextID++
	pl.id = s.nextID
	pl.ctx, pl.cancel = context.WithCancel(context.Background())
	pl.wg.Add(1)
	if pl.udp != nil {
		go s.serveDatagrams(pl)
	} else {
		go s.serveStreams(pl)
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
		if pl.udp != nil {
			_ = pl.udp.Close()
		}
		if pl.ln != nil {
			_ = pl.ln.Close()
		}
	})
	pl.wg.Wait()
}

func (pl *publicListener) closed() bool { return pl.ctx.Err() != nil }

func (pl *publicListener) info() ListenerInfo {
	return ListenerInfo{
		ID: pl.id, Transport: pl.cfg.Transport, Address: pl.cfg.Address,
		Routed: pl.routed.Load(), Unauthenticated: pl.unauthenticated.Load(), NoSpace: pl.noSpace.Load(),
		StreamsOverloaded: pl.streamsOverloaded.Load(),
		Rejected:          pl.router.Rejected(),
	}
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
		n, from, err := pl.udp.ReadFromUDPAddrPort(buf)
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
		peer, verdict := pl.router.RouteDatagram(d)
		var r *route
		if verdict != transport.Unknown {
			r = (*s.routes.Load())[peer.Space]
		}
		switch {
		case verdict == transport.Unknown:
			pl.unauthenticated.Add(1)
		case r == nil:
			pl.noSpace.Add(1)
		case verdict == transport.Stale:
			r.counters.stale.Add(1)
		case verdict == transport.Replayed:
			r.counters.replayed.Add(1)
		case verdict == transport.Routed:
			pl.routed.Add(1)
			s.forward(r, pl.id, peer.Node, from, d)
			continue
		}
		pl.camouflage().Datagram(d, net.UDPAddrFromAddrPort(from))
	}
}

// forward hands one live datagram of link node to r's worker, without
// blocking, and charges r's fair share once the worker's socket took it.
func (s *shared) forward(r *route, listener uint32, node transport.NodeID, from netip.AddrPort, d []byte) {
	ws := r.end.Load()
	if ws == nil {
		r.counters.noWorker.Add(1)
		return
	}
	if s.fair != nil && !s.fair.Allow(r.space, len(d)) {
		r.counters.overShare.Add(1)
		return
	}
	key := keyOf(listener, from)
	if err := ws.data.TrySendDatagram(ipc.DatagramHeader{Listener: listener, Remote: key.addr}, d); err != nil {
		if errors.Is(err, ipc.ErrFull) {
			r.counters.workerFull.Add(1)
		} else {
			r.counters.noWorker.Add(1) // its socket is going away
		}
		return
	}
	r.counters.forwarded.Add(1)
	r.counters.forwardedBytes.Add(uint64(len(d)))
	r.remember(node, key, from, s.now())
	if s.fair != nil {
		s.fair.Charge(r.space, len(d))
	}
}

// remember makes the remote end of a live datagram of link node a
// destination for the space's replies for replyWindow. The link keeps its
// latest replyPeersPerLink remote ends; a new one evicts the link's oldest.
func (r *route) remember(node transport.NodeID, key replyKey, to netip.AddrPort, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(now)
	lr := r.links[node]
	if lr == nil {
		lr = &linkRemotes{}
		r.links[node] = lr
	}
	if rm := r.remotes[key]; rm != nil {
		for i := range lr.n {
			if lr.entries[i].key == key {
				lr.entries[i].at = now
				rm.at, rm.to = now, to
				return
			}
		}
	}
	if lr.n == replyPeersPerLink {
		oldest := 0
		for i := 1; i < lr.n; i++ {
			if lr.entries[i].at.Before(lr.entries[oldest].at) {
				oldest = i
			}
		}
		r.release(lr.entries[oldest].key)
		lr.n--
		lr.entries[oldest] = lr.entries[lr.n]
		r.counters.replyPeersEvicted.Add(1)
	}
	lr.entries[lr.n].key, lr.entries[lr.n].at = key, now
	lr.n++
	rm := r.remotes[key]
	if rm == nil {
		rm = &remote{}
		r.remotes[key] = rm
	}
	rm.holders++
	rm.at, rm.to = now, to
}

// release drops one link's hold on a remote end; r.mu held.
func (r *route) release(key replyKey) {
	if rm := r.remotes[key]; rm != nil {
		if rm.holders--; rm.holders <= 0 {
			delete(r.remotes, key)
		}
	}
}

// sweep drops expired remote ends, at most once per replySweep; r.mu held.
func (r *route) sweep(now time.Time) {
	if now.Sub(r.swept) < replySweep {
		return
	}
	r.swept = now
	for node, lr := range r.links {
		for i := 0; i < lr.n; {
			if now.Sub(lr.entries[i].at) <= replyWindow {
				i++
				continue
			}
			r.release(lr.entries[i].key)
			lr.n--
			lr.entries[i] = lr.entries[lr.n]
		}
		if lr.n == 0 {
			delete(r.links, node)
		}
	}
}

// replyTo is where a reply to key goes, if the worker may send one.
func (r *route) replyTo(key replyKey, now time.Time) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rm := r.remotes[key]
	if rm == nil || now.Sub(rm.at) > replyWindow {
		return netip.AddrPort{}, false
	}
	return rm.to, true
}

// reply sends a datagram a space's worker wrote out through the public
// socket it names. A worker may only answer: the destination must be a
// remote end one of its own links' live (authenticated, fresh, not
// replayed) datagrams came from, through that listener, within
// replyWindow. So a worker can't use the node's public address to reach
// anyone else, whatever egress its space has.
func (s *shared) reply(space transport.SpaceID, h ipc.DatagramHeader, d []byte) {
	r := (*s.routes.Load())[space]
	if r == nil {
		return
	}
	pl := (*s.byID.Load())[h.Listener]
	if pl == nil || pl.udp == nil {
		r.counters.repliesNoListener.Add(1)
		return
	}
	to, ok := r.replyTo(keyOf(h.Listener, h.Remote), s.now())
	if !ok {
		r.counters.repliesNotAllowed.Add(1)
		return
	}
	if s.fair != nil && !s.fair.Allow(space, len(d)) {
		r.counters.repliesOverShare.Add(1)
		return
	}
	if _, err := pl.udp.WriteToUDPAddrPort(d, to); err != nil {
		r.counters.replyErrors.Add(1)
		return
	}
	r.counters.replies.Add(1)
	r.counters.replyBytes.Add(uint64(len(d)))
	if s.fair != nil {
		s.fair.Charge(space, len(d))
	}
}

// serveStreams accepts connections on a public stream listener until it
// closes; each is routed on its own goroutine, at most maxRoutingStreams at
// once, so a slow one holds up no other.
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
		select {
		case pl.routing <- struct{}{}:
		default:
			pl.streamsOverloaded.Add(1)
			pl.camouflage().Stream(conn, nil)
			continue
		}
		pl.wg.Add(1)
		go func() {
			defer pl.wg.Done()
			defer func() { <-pl.routing }()
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
	switch {
	case !ok:
		pl.unauthenticated.Add(1)
	case r == nil:
		pl.noSpace.Add(1)
	}
	if r == nil {
		pl.camouflage().Stream(conn, consumed)
		return
	}
	pl.routed.Add(1)
	defer func() { _ = conn.Close() }() // the worker has its own descriptor
	ws := r.end.Load()
	if ws == nil {
		r.counters.streamsRefused.Add(1)
		return
	}
	f, err := fileOf(conn)
	if err != nil {
		r.counters.streamsRefused.Add(1)
		s.log.Warn("handing over a connection", "err", err)
		return
	}
	defer func() { _ = f.Close() }()
	if err := ws.control.TrySend(ipc.StreamMessage(pl.id, f, consumed)); err != nil {
		r.counters.streamsRefused.Add(1)
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
