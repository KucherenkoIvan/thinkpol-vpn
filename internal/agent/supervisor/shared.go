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
	// Camouflage, for a datagram listener only, gets whatever fails
	// authentication, or is too old or replayed; nil drops it (udp's own
	// default). It must not block for long: the listener reads on only
	// after it returns. A stream listener always turns away to its
	// transport's own (reality splices to its target): SetListeners
	// refuses one with a Camouflage.
	Camouflage transport.Camouflage
}

// FairShare decides how much of the shared listeners each space may use
// (PRD N7; TP-040 fills it in with per-space token buckets). The supervisor
// asks Allow before it forwards a datagram to a worker or sends a worker's
// reply, and charges what the worker's socket accepted or what went out.
// Both are called from several goroutines and on every datagram, so they
// must be cheap and never block. Handed-over streams never pass through
// here (docs/design/server-agent.md "Fair share").
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
	// maxRoutingStreams were in their routing work: they went to the
	// camouflage. StreamsBoundClosed counts those the transport closed
	// past its own bounds (reality's connections being decided or
	// spliced): a flood, or splices pinned open.
	StreamsOverloaded, StreamsBoundClosed uint64
	// Rejected lists the peer links the transport's router can't use, e.g.
	// two links (of the same space or of two) sharing a secret: both are
	// dropped rather than one guessed.
	Rejected []transport.PeerError
}

// SharedCounters are what the shared listeners did for one space; the
// supervisor sends them to the space's worker for its telemetry.
type SharedCounters = ipc.SharedCounters

const (
	// streamRouteTimeout bounds how long a new connection may take to show
	// the router who it is.
	streamRouteTimeout = 10 * time.Second
	// maxRoutingStreams bounds the connections one listener has in their
	// routing work at once (until RouteStream's waiting: for reality, the
	// dial to the target); more go straight to the camouflage. Connections
	// waiting on their dialer's bytes are the transport's own bound.
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
	// known are the listener ids the worker process answered with last
	// (ListenersKnown); nil before its first answer.
	known atomic.Pointer[map[uint32]bool]
	// listenersSent and listenersAnswered count the Listeners messages
	// sent to the process and its answers: it answers each once, in order.
	listenersSent, listenersAnswered atomic.Int64
}

// sendListeners sends the worker process a Listeners message through
// send, counted before it goes: the answer may come before send returns.
func (ws *workerSockets) sendListeners(m ipc.Message, send func(ipc.Message) error) error {
	ws.listenersSent.Add(1)
	if err := send(m); err != nil {
		ws.listenersSent.Add(-1)
		return err
	}
	return nil
}

// unanswered is how many Listeners messages the process hasn't answered.
func (ws *workerSockets) unanswered() int64 {
	return ws.listenersSent.Load() - ws.listenersAnswered.Load()
}

// knows reports whether the worker answered with every listener in ls.
func (ws *workerSockets) knows(ls []ipc.Listener) bool {
	known := ws.known.Load()
	for _, l := range ls {
		if known == nil || !(*known)[l.ID] {
			return false
		}
	}
	return true
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
	// answerTimeout bounds how long serveOpened waits for the workers to
	// know a new listener (the supervisor's StopTimeout); zero doesn't
	// wait.
	answerTimeout time.Duration
	// waiting, if set (tests), is called each time serveOpened waits.
	waiting func()

	changeMu sync.Mutex
	// changed is closed, and replaced, whenever a worker answers a
	// Listeners message, a worker is attached or detached, or the
	// listeners change.
	changed chan struct{}

	mu        sync.Mutex // setSpaces and setListeners
	nextID    uint32
	listeners map[string]*publicListener // by transport and address
	tables    map[string]*transport.PeerTable
	// packetRouters and streamRouters hold one router per transport,
	// shared by all its listeners and kept across their reopens: replay
	// state is per credential, not per socket.
	packetRouters map[string]transport.PacketRouter
	streamRouters map[string]transport.StreamRouter
	closed        bool

	// Read on every datagram, so swapped as a whole.
	routes atomic.Pointer[map[transport.SpaceID]*route]
	byID   atomic.Pointer[map[uint32]*publicListener]
	// inboundTransports is, per space, the transports its inbound table
	// has links of: a stream listener's handoff settings go only to those
	// spaces' workers.
	inboundTransports atomic.Pointer[map[transport.SpaceID]map[string]bool]
}

func newShared(reg *transport.Registry, fair FairShare, log *slog.Logger, now func() time.Time) *shared {
	s := &shared{
		reg: reg, fair: fair, log: log, now: now, routingLimit: maxRoutingStreams,
		listeners: map[string]*publicListener{}, tables: map[string]*transport.PeerTable{},
		packetRouters: map[string]transport.PacketRouter{}, streamRouters: map[string]transport.StreamRouter{},
		changed: make(chan struct{}),
	}
	s.routes.Store(&map[transport.SpaceID]*route{})
	s.byID.Store(&map[uint32]*publicListener{})
	s.inboundTransports.Store(&map[transport.SpaceID]map[string]bool{})
	return s
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
	// A datagram transport's socket and router, or a stream transport's.
	udp     *net.UDPConn
	packets transport.PacketRouter
	ln      transport.StreamListener
	streams transport.StreamRouter
	camo    atomic.Pointer[transport.Camouflage] // a datagram listener's, as configured: nil drops
	ctx     context.Context                      // ends when the listener closes
	cancel  context.CancelFunc
	closing sync.Once
	wg      sync.WaitGroup
	routing chan struct{} // a token per stream being routed
	serving bool          // its serve loop started; s.mu

	routed, unauthenticated, noSpace, streamsOverloaded, streamsBoundClosed atomic.Uint64
}

func listenerKey(l Listener) string { return l.Transport + " " + l.Address }

// rejected are the peer links the listener's router can't use.
func (pl *publicListener) rejected() []transport.PeerError {
	if pl.packets != nil {
		return pl.packets.Rejected()
	}
	return pl.streams.Rejected()
}

// setSpaces makes the merged credential tables and the routes those of
// inbound: per space, the links each transport accepts, from the space's
// own map. Every entry's Space is stamped with the space it is listed
// under, whatever it said. It returns the spaces served before and after
// whose inbound transports changed: their workers' Listeners message
// changes with them.
func (s *shared) setSpaces(inbound map[transport.SpaceID]map[string][]transport.PeerLink) (listenersChanged []transport.SpaceID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldTransports := *s.inboundTransports.Load()
	transports := make(map[transport.SpaceID]map[string]bool, len(inbound))
	for space, byName := range inbound {
		transports[space] = map[string]bool{}
		for name, links := range byName {
			if len(links) > 0 {
				transports[space][name] = true
			}
		}
		if old, ok := oldTransports[space]; ok && !maps.Equal(old, transports[space]) {
			listenersChanged = append(listenersChanged, space)
		}
	}
	s.announceGained(oldTransports, transports, listenersChanged)
	// Routes before tables: a link that authenticates has a route.
	old := *s.routes.Load()
	routes := make(map[transport.SpaceID]*route, len(inbound))
	for space := range inbound {
		r := old[space]
		if r == nil {
			r = &route{space: space, peers: newReplyPeers()}
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
	s.inboundTransports.Store(&transports)
	return listenersChanged
}

// announceGained sends the running worker of each changed space that
// gains a transport its Listeners, old and new transports listed, before
// setSpaces routes the new links: a member routed first would reach a
// worker that doesn't know the listener and be closed. It relies on the
// control socket's order, not on the worker's answer: what is handed
// over after it takes the descriptor's write lock after it, and only
// streams, on the same socket, come of the new links (a datagram
// listener is in every space's Listeners already). The send doesn't wait
// for room in the control socket (a full one drops it), but it takes
// that write lock, which the session's own sends hold while they wait
// for room: a backed-up worker stalls it, s.mu held, while those sends
// wait, each for up to StopTimeout. The caller signals every changed
// space anyway, which sends the final listing, and a dialer routed while
// a full socket dropped it retries. Counted as sent: the worker answers
// it too. s.mu held.
func (s *shared) announceGained(old, now map[transport.SpaceID]map[string]bool, changed []transport.SpaceID) {
	var gaining []transport.SpaceID
	transition := maps.Clone(old)
	for _, space := range changed {
		union := maps.Clone(old[space])
		maps.Copy(union, now[space])
		if len(union) > len(old[space]) {
			transition[space] = union
			gaining = append(gaining, space)
		}
	}
	if len(gaining) == 0 {
		return
	}
	s.inboundTransports.Store(&transition)
	routes := *s.routes.Load()
	for _, space := range gaining {
		r := routes[space]
		if r == nil {
			continue
		}
		ws := r.end.Load()
		if ws == nil {
			continue
		}
		if m, err := ipc.ListenersMessage(s.ipcListeners(space)); err == nil {
			_ = ws.sendListeners(m, ws.control.TrySend)
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

// packetRouter is the transport's one router over its merged table; s.mu
// held.
func (s *shared) packetRouter(name string, t transport.PacketRoutable) transport.PacketRouter {
	r := s.packetRouters[name]
	if r == nil {
		r = t.PacketRouter(s.table(name))
		s.packetRouters[name] = r
	}
	return r
}

// streamRouter is the transport's one router over its merged table; s.mu
// held.
func (s *shared) streamRouter(name string, t transport.StreamRoutable) transport.StreamRouter {
	r := s.streamRouters[name]
	if r == nil {
		r = t.StreamRouter(s.table(name))
		s.streamRouters[name] = r
	}
	return r
}

// openListeners opens, keeps and closes public listeners so the node
// listens on exactly ls. A listener whose transport, address and settings
// stay keeps its socket (and its id). One whose settings changed is closed
// and opened again, under a new id: its port is free in between, and lost
// if the reopen fails (reported, the others served). The listeners it
// opens, opened, aren't served yet (serveOpened): what connects meanwhile
// waits in their sockets. changed reports whether the set changed, for
// the workers' Listeners message.
func (s *shared) openListeners(ctx context.Context, ls []Listener) (opened []uint32, changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, errors.New("supervisor: closed")
	}
	want := make(map[string]Listener, len(ls))
	var errs []error
	for _, l := range ls {
		k := listenerKey(l)
		if _, dup := want[k]; dup {
			return nil, false, fmt.Errorf("supervisor: listener %s listed twice", k)
		}
		if t, ok := s.transport(l.Transport); ok && l.Camouflage != nil {
			if _, stream := t.(transport.StreamRoutable); stream {
				errs = append(errs, fmt.Errorf("supervisor: listener %s: a stream listener turns away to its transport's own camouflage", k))
				continue
			}
		}
		want[k] = l
	}
	for k, pl := range s.listeners {
		if l, ok := want[k]; ok && string(l.Settings) == pl.settings {
			pl.setCamouflage(l.Camouflage)
			continue
		}
		pl.close()
		delete(s.listeners, k)
		changed = true
	}
	for _, l := range ls {
		k := listenerKey(l)
		if _, ok := s.listeners[k]; ok {
			continue
		}
		if _, ok := want[k]; !ok {
			continue // refused above
		}
		pl, err := s.open(ctx, l)
		if err != nil {
			errs = append(errs, fmt.Errorf("supervisor: listener %s: %w", k, err))
			continue
		}
		s.listeners[k] = pl
		opened = append(opened, pl.id)
		changed = true
	}
	byID := make(map[uint32]*publicListener, len(s.listeners))
	for _, pl := range s.listeners {
		byID[pl.id] = pl
	}
	s.byID.Store(&byID)
	if changed {
		s.wake() // a listener serveOpened waits on may be gone
	}
	return opened, changed, errors.Join(errs...)
}

// transport is the registry's transport called name.
func (s *shared) transport(name string) (transport.Transport, bool) {
	if s.reg == nil {
		return nil, false
	}
	return s.reg.Get(name)
}

// open opens one public listener, not served yet; s.mu held.
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
		pl.packets = s.packetRouter(l.Transport, t)
	case transport.StreamRoutable:
		r := s.streamRouter(l.Transport, t)
		ln, err := t.ListenStream(ctx, cfg, r)
		if err != nil {
			return nil, err
		}
		pl.ln = ln
		pl.streams = r
	default:
		return nil, errors.New("the transport can't sit behind a shared listener")
	}
	s.nextID++
	pl.id = s.nextID
	pl.ctx, pl.cancel = context.WithCancel(context.Background())
	return pl, nil
}

// serveOpened starts serving the listeners ids that openListeners
// opened, once every served space's worker that may be routed one
// (ipcListeners) is routed to and has answered with it: a connection
// routed to a space with no worker attached is refused, and one handed to
// a worker that doesn't have its listener's id is closed there. A worker
// starting or restarting gets the listeners in its first Listeners
// message and is attached once it has answered for all of them
// (attachKnowing). The wait ends at answerTimeout, so a worker that
// doesn't answer, or doesn't start, holds up no other space for longer:
// its session kills one that leaves a Listeners message unanswered for
// StopTimeout. A listener closed meanwhile is never served.
func (s *shared) serveOpened(ids []uint32) {
	if len(ids) == 0 {
		return
	}
	timeout := time.NewTimer(s.answerTimeout)
	defer timeout.Stop()
wait:
	for {
		changed := s.changes()
		lagging := s.laggingSpaces(ids)
		if lagging == 0 {
			break
		}
		if s.waiting != nil {
			s.waiting()
		}
		select {
		case <-changed:
		case <-timeout.C:
			s.log.Warn("serving new listeners before every worker knows them", "spaces", lagging, "waited", s.answerTimeout)
			break wait
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	byID := *s.byID.Load()
	for _, id := range ids {
		pl := byID[id]
		if pl == nil || pl.serving {
			continue
		}
		pl.serving = true
		pl.wg.Add(1)
		if pl.udp != nil {
			go s.serveDatagrams(pl)
		} else {
			go s.serveStreams(pl)
		}
	}
}

// laggingSpaces counts the served spaces that may be routed one of the
// listeners ids not served yet and whose worker isn't attached, or hasn't
// answered with it.
func (s *shared) laggingSpaces(ids []uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0
	}
	byID := *s.byID.Load()
	waiting := map[uint32]bool{}
	for _, id := range ids {
		if pl := byID[id]; pl != nil && !pl.serving {
			waiting[id] = true
		}
	}
	if len(waiting) == 0 {
		return 0
	}
	lagging := 0
	for space, r := range *s.routes.Load() {
		ls := slices.DeleteFunc(s.ipcListeners(space), func(l ipc.Listener) bool { return !waiting[l.ID] })
		if len(ls) == 0 {
			continue
		}
		if ws := r.end.Load(); ws == nil || !ws.knows(ls) {
			lagging++
		}
	}
	return lagging
}

// changes is closed at the next answer, attach, detach or change of the
// listeners: taken before a check, so none is missed.
func (s *shared) changes() <-chan struct{} {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	return s.changed
}

// wake closes changes' channel.
func (s *shared) wake() {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	close(s.changed)
	s.changed = make(chan struct{})
}

// setKnown records a worker process's answer to a Listeners message: the
// listener ids it has now. An answer to no Listeners message is a
// protocol error.
func (s *shared) setKnown(ws *workerSockets, ids []uint32) error {
	if ws.listenersAnswered.Add(1) > ws.listenersSent.Load() {
		return errors.New("a listeners known answering no listeners message")
	}
	known := make(map[uint32]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	ws.known.Store(&known)
	s.wake()
	return nil
}

func (pl *publicListener) setCamouflage(c transport.Camouflage) { pl.camo.Store(&c) }

// camouflage is where the listener sends what it turns away itself: a
// stream listener's transport's own, a datagram listener's configured
// one (nil drops).
func (pl *publicListener) camouflage() transport.Camouflage {
	if pl.ln != nil {
		return pl.ln.Camouflage()
	}
	return transport.OrDrop(*pl.camo.Load())
}

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
		StreamsOverloaded: pl.streamsOverloaded.Load(), StreamsBoundClosed: pl.streamsBoundClosed.Load(),
		Rejected: pl.rejected(),
	}
}

// ipcListeners is what space's worker is told about the listeners: each
// datagram listener, and each stream listener of a transport the space's
// inbound table has links of, with its handoff settings (reality's
// private key and target among them), so a space that can't be routed a
// listener's connections never holds them.
func (s *shared) ipcListeners(space transport.SpaceID) []ipc.Listener {
	byID := *s.byID.Load()
	transports := (*s.inboundTransports.Load())[space]
	out := make([]ipc.Listener, 0, len(byID))
	for _, pl := range byID {
		l := ipc.Listener{ID: pl.id, Transport: pl.cfg.Transport, Stream: pl.ln != nil}
		if pl.ln != nil {
			if !transports[pl.cfg.Transport] {
				continue
			}
			l.Address = pl.ln.Addr().String()
			l.Handoff = pl.ln.HandoffSettings()
		} else {
			l.Address = pl.udp.LocalAddr().String()
		}
		out = append(out, l)
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
	s.wake()
	for _, pl := range ls {
		pl.close()
	}
}

// attachKnowing attaches ws, as attach does, only if its worker has
// answered with every listener it may be routed: a worker's first
// Listeners may predate the latest set, and what it is routed must name a
// listener it has. s.mu keeps the set as checked until ws is attached, so
// a listener opened after that waits for ws's answer too (serveOpened).
func (s *shared) attachKnowing(space transport.SpaceID, ws *workerSockets) (detach func(), ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ws.knows(s.ipcListeners(space)) {
		return nil, false
	}
	return s.attach(space, ws), true
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
	s.wake()
	return func() {
		if r.end.CompareAndSwap(ws, nil) {
			s.wake()
		}
	}
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
		peer, verdict := pl.packets.RouteDatagram(d)
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
// blocking, remembers its source as an address the worker may answer,
// and charges r's fair share once the worker's socket took it.
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
	// Remembered before the worker has the datagram: the worker is another
	// process and may answer before TrySendDatagram returns. A failed
	// hand-off still counts: the datagram was authenticated, fresh and
	// not replayed, which is all the reply rule asks.
	if r.peers.remember(node, key, from, s.now()) {
		r.counters.replyPeersEvicted.Add(1)
	}
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
	if s.fair != nil {
		s.fair.Charge(r.space, len(d))
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
			done := sync.OnceFunc(func() { <-pl.routing })
			defer done()
			s.routeStream(pl, conn, done)
		}()
	}
}

// routeStream lets the listener read the start of conn and decide it:
// what it hands over (descriptors and the bytes it read) goes to its
// space's worker; what it turns away it sends to its camouflage itself.
// waiting lets go of the connection's routing slot.
func (s *shared) routeStream(pl *publicListener, conn net.Conn, waiting func()) {
	_ = conn.SetReadDeadline(s.now().Add(streamRouteTimeout))
	stop := context.AfterFunc(pl.ctx, func() { _ = conn.SetReadDeadline(time.Unix(1, 0)) })
	serves := func(peer transport.Identity) bool { return (*s.routes.Load())[peer.Space] != nil }
	h, verdict := pl.ln.RouteStream(conn, serves, waiting)
	stop()
	var r *route
	if verdict != transport.StreamUnknown && verdict != transport.StreamBoundClosed {
		r = (*s.routes.Load())[h.Peer.Space]
	}
	switch {
	case verdict == transport.StreamUnknown:
		pl.unauthenticated.Add(1)
		return
	case verdict == transport.StreamBoundClosed:
		pl.streamsBoundClosed.Add(1)
		return
	case verdict == transport.StreamUnserved || r == nil:
		pl.noSpace.Add(1)
		h.Close() // a space dropped since it was asked
		return
	case verdict == transport.StreamStale:
		r.counters.stale.Add(1)
		return
	case verdict == transport.StreamReplayed:
		r.counters.replayed.Add(1)
		return
	}
	_ = h.Conn.SetReadDeadline(time.Time{})
	pl.routed.Add(1)
	defer h.Close() // the worker has its own descriptors
	ws := r.end.Load()
	if ws == nil {
		r.counters.streamsRefused.Add(1)
		return
	}
	files, err := filesOf(h)
	if err != nil {
		r.counters.streamsRefused.Add(1)
		s.log.Warn("handing over a connection", "err", err)
		return
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	var target *os.File
	if len(files) == 2 {
		target = files[1]
	}
	m := ipc.StreamMessage(ipc.Stream{Listener: pl.id, Consumed: h.Consumed, TargetRead: h.TargetRead}, files[0], target)
	if err := ws.control.TrySend(m); err != nil {
		r.counters.streamsRefused.Add(1)
		return
	}
	r.counters.streams.Add(1)
}

// filesOf duplicates a handoff's descriptors (its connection's, then its
// target's, if any) for passing to a worker.
func filesOf(h transport.StreamHandoff) ([]*os.File, error) {
	f, err := fileOf(h.Conn)
	if err != nil {
		return nil, err
	}
	if h.Target == nil {
		return []*os.File{f}, nil
	}
	tf, err := fileOf(h.Target)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return []*os.File{f, tf}, nil
}

// fileOf duplicates a connection's descriptor for passing to a worker.
func fileOf(conn net.Conn) (*os.File, error) {
	fc, ok := conn.(interface{ File() (*os.File, error) })
	if !ok {
		return nil, fmt.Errorf("a %T has no descriptor to hand over", conn)
	}
	return fc.File()
}
