package path

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Range is a span of durations a node draws from, Min and Max included.
type Range struct{ Min, Max time.Duration }

func (r Range) check(name string) error {
	if r.Min <= 0 || r.Max < r.Min {
		return fmt.Errorf("path: %s range %v–%v: want 0 < Min ≤ Max", name, r.Min, r.Max)
	}
	return nil
}

// Options tune liveness, failover and queues. The zero value of a field
// means its default. The liveness terms are docs/design/path-liveness.md's.
type Options struct {
	// Burst is S's range (default 500 ms–1.5 s), drawn at each answer: a
	// frame written S after both the latest answer and the previous frame
	// opens a burst. On a shaped link the top shrinks by D, never below
	// Min.
	Burst Range
	// Response bounds R, the time a link waits for an answer before it
	// turns suspect: the probes' smoothed round trip plus four deviations,
	// clamped to it (default 250 ms–1 s); Max until measured.
	Response Range
	// Idle is I's range per transport name: a link that got no answer for
	// I probes. Transports it doesn't list take the defaults, 8–24 s for
	// "reality" and IdleDefault for the rest.
	Idle map[string]Range
	// IdleDefault is I's range for transports Idle doesn't list (default
	// 5–14 s, udp's).
	IdleDefault Range
	// ControlHold is the longest each end's transport may hold a control
	// frame (default transport.MaxControlHold). A suspect link waits
	// T = 2·ControlHold + D + R for an answer before it is closed.
	ControlHold time.Duration
	// DialTimeout is how long a dial, and a link that was never answered,
	// may take (default 6 s). Neighbors lists a dialed node that never
	// gave a link as down once it has passed.
	DialTimeout time.Duration
	// Rand is where the draws (S, I, a link's first seq) come from
	// (default crypto/rand.Reader); safe for one reader at a time.
	Rand io.Reader
	// FollowFor is how long the leader's latest path stays worth following
	// after its last packet (default DialTimeout).
	FollowFor time.Duration
	// RedialMin and RedialMax bound the backoff between dials of one
	// adjacent node (defaults 250 ms and 5 s); RedialMax ≥ RedialMin.
	RedialMin, RedialMax time.Duration
	// HopLimit is what this node's packets start with and the most a
	// packet it relays may keep (default DefaultHopLimit).
	HopLimit uint8
	// QueueLen is each link's send queue, in packets (default 256). A full
	// queue drops.
	QueueLen int
	// Selector picks first hops for peers and next hops for routes that
	// don't bring their own (default Failover with a 20 s hold-down).
	Selector Selector
	// Space is the node's space: Serve refuses links whose listener says
	// they belong to another.
	Space transport.SpaceID
	// Now is the clock (default time.Now). It must be monotonic: the node
	// only ever subtracts its readings. Timers (liveness deadlines, dial
	// backoff) run on the wall clock.
	Now func() time.Time
	// Log gets the links' lives at info level: up, closed and why, the
	// first failed dial of a run and the first failed read or write of a
	// link (the rest at debug). Nil discards them.
	Log *slog.Logger

	watchEvery time.Duration // how often links' remotes are checked (tests)
	// afterFunc starts the links' deadline timers (tests run them on a
	// fake clock).
	afterFunc func(time.Duration, func()) timer
}

// timer is the part of *time.Timer a link's deadline needs.
type timer interface {
	Reset(time.Duration) bool
	Stop() bool
}

// defaultIdle are the idle ranges of transports with their own
// (docs/design/path-liveness.md, owner's decision 2).
var defaultIdle = map[string]Range{"reality": {8 * time.Second, 24 * time.Second}}

func (o Options) withDefaults() (Options, error) {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	defRange := func(r *Range, v Range) {
		if *r == (Range{}) {
			*r = v
		}
	}
	defRange(&o.Burst, Range{500 * time.Millisecond, 1500 * time.Millisecond})
	defRange(&o.Response, Range{250 * time.Millisecond, time.Second})
	defRange(&o.IdleDefault, Range{5 * time.Second, 14 * time.Second})
	idle := maps.Clone(defaultIdle)
	maps.Copy(idle, o.Idle)
	o.Idle = idle
	def(&o.ControlHold, transport.MaxControlHold)
	def(&o.DialTimeout, 6*time.Second)
	def(&o.FollowFor, o.DialTimeout)
	def(&o.RedialMin, 250*time.Millisecond)
	def(&o.RedialMax, max(5*time.Second, o.RedialMin))
	def(&o.watchEvery, 500*time.Millisecond)
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.afterFunc == nil {
		o.afterFunc = func(d time.Duration, f func()) timer { return time.AfterFunc(d, f) }
	}
	if o.HopLimit == 0 {
		o.HopLimit = DefaultHopLimit
	}
	if o.QueueLen <= 0 {
		o.QueueLen = 256
	}
	if o.Selector == nil {
		o.Selector = Failover{HoldDown: 20 * time.Second}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	errs := []error{o.Burst.check("Burst"), o.Response.check("Response"), o.IdleDefault.check("IdleDefault")}
	for name, r := range o.Idle {
		errs = append(errs, r.check("Idle["+name+"]"))
		if r.Min <= o.Burst.Max {
			errs = append(errs, fmt.Errorf("path: Idle[%s] starts at %v, within Burst's %v", name, r.Min, o.Burst.Max))
		}
	}
	if o.IdleDefault.Min <= o.Burst.Max {
		errs = append(errs, fmt.Errorf("path: IdleDefault starts at %v, within Burst's %v", o.IdleDefault.Min, o.Burst.Max))
	}
	if o.RedialMax < o.RedialMin {
		errs = append(errs, fmt.Errorf("path: RedialMax %v is below RedialMin %v", o.RedialMax, o.RedialMin))
	}
	return o, errors.Join(errs...)
}

// Table is what a node's map section says about adjacency and forwarding.
// The engine builds it from the section (see package dataplane).
type Table struct {
	// Links are the adjacent nodes this node dials. Adjacent nodes that
	// dial this node arrive through Serve instead.
	Links []Link
	// Routes are the forwarding table. A node relays a packet only along
	// a route for its destination, and only from a source it knows: one it
	// has a route to, or an adjacent node.
	Routes []Route
}

// Link is an adjacent node this node keeps a link to.
type Link struct {
	Node NodeID
	// Endpoints are the ways to reach it, in priority order. The order
	// applies when dialing: a link carries on through the endpoint it got,
	// and the first endpoint is tried again only once that link dies.
	Endpoints []Endpoint
}

// Endpoint is one way to dial an adjacent node: a transport's dialer, the
// address, and what the map says about the link.
type Endpoint struct {
	// Transport is the transport's name in the registry, for status.
	Transport string
	Dialer    transport.Dialer
	Address   string
	Config    transport.DialConfig
}

// Route sends packets for Destination through one of NextHops, adjacent
// nodes in priority order; a next hop may be the destination itself.
type Route struct {
	Destination NodeID
	NextHops    []NodeID
	// Selector picks among NextHops; nil means the node's. Its state, if
	// any, is its own: pass the same value again to keep it.
	Selector Selector
}

// Node is one node's path layer: its links to adjacent nodes, its
// forwarding table, and the Binds of its WireGuard devices. It relays
// packets addressed to other nodes along its routes, delivers packets
// addressed to it to the Bind that has their source as a peer, and drops
// everything else.
type Node struct {
	id    NodeID
	opts  Options
	start time.Time

	ctx    context.Context
	cancel context.CancelFunc
	life   sync.Mutex // orders spawn against Close
	wg     sync.WaitGroup

	mu    sync.Mutex // the table, the dials and the Binds' peers
	dials map[NodeID]*dialLoop
	binds map[*Bind]struct{}

	nmu       sync.RWMutex
	neighbors map[NodeID]*neighbor

	routes atomic.Pointer[map[NodeID]*routeState]
	peers  atomic.Pointer[map[NodeID]*peerState] // every Bind's peers

	counters counters

	randMu sync.Mutex // Options.Rand
}

// NewNode starts the path layer of node id. Give it a Table with Update and
// its listeners with Serve.
func NewNode(id NodeID, opts Options) (*Node, error) {
	if id == (NodeID{}) {
		return nil, errors.New("path: zero node id")
	}
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		id: id, opts: opts, start: opts.Now(),
		ctx: ctx, cancel: cancel,
		dials:     make(map[NodeID]*dialLoop),
		binds:     make(map[*Bind]struct{}),
		neighbors: make(map[NodeID]*neighbor),
	}
	n.routes.Store(&map[NodeID]*routeState{})
	n.peers.Store(&map[NodeID]*peerState{})
	n.spawn(n.watch)
	return n, nil
}

// ID is the node's id.
func (n *Node) ID() NodeID { return n.id }

// now is nanoseconds on the node's clock since it started, never zero,
// which means "never" in the timestamps below.
func (n *Node) now() int64 { return max(int64(n.opts.Now().Sub(n.start)), 0) + 1 }

func (n *Node) wall(t int64) time.Time { return n.start.Add(time.Duration(t - 1)) }

// spawn runs f on a goroutine Close waits for, unless the node is closed.
func (n *Node) spawn(f func()) bool {
	n.life.Lock()
	defer n.life.Unlock()
	if n.ctx.Err() != nil {
		return false
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		f()
	}()
	return true
}

// Update replaces the node's table. Links whose endpoints didn't change
// carry on, the rest are closed and dialed anew; routes that stay keep
// their state. Entries naming no node, the node itself, or nowhere to go
// are skipped: the map's reader doesn't rule them out. Adjacent nodes
// nothing refers to any more, and with no link left, are forgotten.
func (n *Node) Update(t Table) {
	want := make(map[NodeID][]Endpoint, len(t.Links))
	for _, l := range t.Links {
		if l.Node == (NodeID{}) || l.Node == n.id || want[l.Node] != nil {
			continue
		}
		var eps []Endpoint
		for _, e := range l.Endpoints {
			if e.Dialer != nil && e.Address != "" {
				eps = append(eps, e)
			}
		}
		if len(eps) > 0 {
			want[l.Node] = eps
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ctx.Err() != nil {
		return
	}
	old := *n.routes.Load()
	routes := make(map[NodeID]*routeState, len(t.Routes))
	for _, r := range t.Routes {
		if r.Destination == (NodeID{}) || r.Destination == n.id || routes[r.Destination] != nil {
			continue
		}
		hops := n.cleanHops(r.NextHops)
		if len(hops) == 0 {
			continue
		}
		rs := old[r.Destination]
		if rs == nil {
			rs = &routeState{dst: r.Destination}
		}
		rs.mu.Lock()
		rs.hops, rs.selector = hops, r.Selector
		rs.mu.Unlock()
		routes[r.Destination] = rs
	}
	n.routes.Store(&routes)

	for id, d := range n.dials {
		if eps, ok := want[id]; !ok || !sameEndpoints(d.endpoints, eps) {
			d.stop()
			delete(n.dials, id)
		}
	}
	for id, eps := range want {
		if _, ok := n.dials[id]; !ok {
			n.dials[id] = n.startDial(id, eps)
		}
	}
	n.pruneLocked()
}

func (n *Node) cleanHops(in []NodeID) []NodeID {
	var hops []NodeID
	for _, h := range in {
		if h != (NodeID{}) && h != n.id && !slices.Contains(hops, h) {
			hops = append(hops, h)
		}
	}
	return hops
}

// pruneLocked forgets adjacent nodes with no link that neither the table
// nor a Bind refers to. Callers hold n.mu.
func (n *Node) pruneLocked() {
	used := make(map[NodeID]bool)
	for id := range n.dials {
		used[id] = true
	}
	for _, rs := range *n.routes.Load() {
		for _, h := range rs.hops {
			used[h] = true
		}
	}
	for _, ps := range *n.peers.Load() {
		for _, h := range *ps.hops.Load() {
			used[h] = true
		}
	}
	n.nmu.Lock()
	defer n.nmu.Unlock()
	for id, nb := range n.neighbors {
		if !used[id] && len(nb.all()) == 0 {
			delete(n.neighbors, id)
		}
	}
}

func sameEndpoints(a, b []Endpoint) bool {
	return slices.EqualFunc(a, b, func(x, y Endpoint) bool {
		return x.Transport == y.Transport && sameDialer(x.Dialer, y.Dialer) && x.Address == y.Address &&
			bytes.Equal(x.Config.Credential, y.Config.Credential) &&
			bytes.Equal(x.Config.Settings, y.Config.Settings) &&
			x.Config.Shaping == y.Config.Shaping
	})
}

// sameDialer compares dialers without panicking on types == can't compare;
// such dialers are never the same, so their links are redialed.
func sameDialer(a, b transport.Dialer) bool {
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	return ta == tb && (ta == nil || ta.Comparable() && a == b)
}

// Serve accepts links from l, a listener of the named transport, until l
// or the node is closed, and returns nil when the node closed first. Each
// accepted link belongs to the adjacent node the listener authenticated;
// links of another space are closed.
func (n *Node) Serve(transportName string, l transport.Listener) error {
	n.life.Lock()
	if n.ctx.Err() != nil {
		n.life.Unlock()
		return nil
	}
	n.wg.Add(1)
	n.life.Unlock()
	defer n.wg.Done()
	for {
		tl, peer, err := l.Accept(n.ctx)
		switch {
		case n.ctx.Err() != nil:
			if tl != nil {
				_ = tl.Close()
			}
			return nil
		case errors.Is(err, net.ErrClosed):
			return err
		case err != nil:
			select {
			case <-n.ctx.Done():
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		switch {
		case peer.Space != n.opts.Space:
			n.counters.otherSpace.Add(1)
			_ = tl.Close()
		case peer.Node == (NodeID{}) || peer.Node == n.id:
			_ = tl.Close()
		default:
			n.addLink(peer.Node, tl, false, transportName, -1, transport.Shaping{})
		}
	}
}

// Close stops the node and closes every link. Binds stop delivering;
// closing them stays with their WireGuard devices.
func (n *Node) Close() error {
	n.life.Lock()
	n.cancel()
	n.life.Unlock()
	n.mu.Lock()
	for id, d := range n.dials {
		d.stop()
		delete(n.dials, id)
	}
	n.mu.Unlock()
	n.nmu.RLock()
	for _, nb := range n.neighbors {
		for _, l := range nb.all() {
			l.close("the node stopped", nil)
		}
	}
	n.nmu.RUnlock()
	n.wg.Wait()
	return nil
}

func (n *Node) lookupNeighbor(id NodeID) *neighbor {
	n.nmu.RLock()
	defer n.nmu.RUnlock()
	return n.neighbors[id]
}

// candidate describes hop h from this node's links to it.
func (n *Node) candidate(h NodeID, now int64) Candidate {
	c := Candidate{Hop: h, HeardVia: -1}
	if nb := n.lookupNeighbor(h); nb != nil {
		nb.describe(&c, now)
	}
	return c
}

// watch logs links' far ends moving and now and then forgets adjacent
// nodes no longer used. Liveness runs on each link's own timer.
func (n *Node) watch() {
	tick := time.NewTicker(n.opts.watchEvery)
	defer tick.Stop()
	var pruned int64
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
		now := n.now()
		if now-pruned >= int64(n.opts.DialTimeout) {
			n.mu.Lock()
			n.pruneLocked()
			n.mu.Unlock()
			pruned = now
		}
		n.nmu.RLock()
		nbs := make([]*neighbor, 0, len(n.neighbors))
		for _, nb := range n.neighbors {
			nbs = append(nbs, nb)
		}
		n.nmu.RUnlock()
		for _, nb := range nbs {
			for _, l := range nb.all() {
				l.watchRemote()
			}
		}
	}
}

// handle takes one frame read from l and owns b from then on.
func (n *Node) handle(l *link, b *[]byte) {
	f := *b
	now := n.now()
	switch f[0] {
	case kindProbe:
		switch len(f) {
		case probeSizeV1:
			if f[1]&flagReadsAcks != 0 {
				l.readsAcks(f[2:6], now)
			}
			l.reply(b)
			return
		case probeSize:
			l.onFrame(now, f, probeSizeV1, 0)
			if f[1]&flagClosing != 0 {
				putBuf(b)
				l.close("the far end closed it", nil)
				return
			}
			l.reply(b)
			return
		}
	case kindProbeReply:
		if len(f) == probeSizeV1 || len(f) == probeSize {
			l.onFrame(now, f, seqAck(f), l.awaited(f))
			putBuf(b)
			return
		}
	case kindPacket, kindPacketV1:
		h, off, ok := parsePacket(f)
		if !ok {
			break
		}
		if k := seqAck(f); k >= 0 {
			l.onFrame(now, f, k, 0)
		}
		// Packets moving to another of the neighbor's links hint that the
		// one they came on before went silent.
		if prev := l.nb.lastRecv.Swap(l); prev != nil && prev != l && !prev.closed() {
			prev.hint(now)
		}
		if h.dst == n.id {
			n.deliver(h.src, l.nb.id, b, off)
		} else {
			n.forward(l, h, b)
		}
		return
	}
	n.counters.malformed.Add(1)
	putBuf(b)
}

// reply turns a probe in b into its reply and queues it. A link that reads
// acks says so; one that doesn't echoes the probe's flags, as older nodes
// do.
func (l *link) reply(b *[]byte) {
	f := (*b)[:probeSize]
	if len(*b) == probeSizeV1 {
		clear(f[probeSizeV1:])
	}
	f[0] = kindProbeReply
	l.lmu.Lock()
	if l.lv.newer {
		f[1] = flagReadsAcks
	}
	l.lmu.Unlock()
	*b = f
	l.sendControl(b)
}

func (n *Node) deliver(src, via NodeID, b *[]byte, off int) {
	ps := (*n.peers.Load())[src]
	if ps == nil {
		n.counters.unknownPeer.Add(1)
		putBuf(b)
		return
	}
	ps.bind.Load().deliver(ps, via, b, off, n.now())
}

// forward relays a packet along this node's route for its destination,
// never back to the neighbor it came from. Its source must be a node this
// node knows (a loose reverse-path check): one it has a route to, or an
// adjacent node. A strict check would drop legitimate traffic on maps whose
// routes aren't symmetric.
func (n *Node) forward(from *link, h header, b *[]byte) {
	routes := *n.routes.Load()
	rs := routes[h.dst]
	hops := min(h.hopLimit, n.opts.HopLimit)
	switch {
	case rs == nil:
		n.counters.noRoute.Add(1)
	case h.src != from.nb.id && routes[h.src] == nil && n.lookupNeighbor(h.src) == nil:
		n.counters.spoofed.Add(1)
	case hops <= 1:
		n.counters.hopLimit.Add(1)
	default:
		to := rs.pick(n, from.nb.id)
		if to == nil {
			n.counters.noPath.Add(1)
			break
		}
		(*b)[1] = hops - 1
		if to.send(b) {
			n.counters.forwarded.Add(1)
		}
		return
	}
	putBuf(b)
}

// routeState is one route and the next hop in use.
type routeState struct {
	dst NodeID

	mu       sync.Mutex
	hops     []NodeID
	selector Selector
	current  NodeID
	since    int64
	cands    []Candidate
}

// pick chooses the next hop's link, never exclude (split horizon), by the
// route's selector on link liveness alone: relays don't follow.
func (rs *routeState) pick(n *Node, exclude NodeID) *link {
	now := n.now()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	cands := rs.cands[:0]
	for _, h := range rs.hops {
		c := Candidate{Hop: h, HeardVia: -1}
		if h != exclude {
			c = n.candidate(h, now)
		}
		cands = append(cands, c)
	}
	rs.cands = cands
	sel := rs.selector
	if sel == nil {
		sel = n.opts.Selector
	}
	hop, ok := sel.Select(Choice{Current: rs.current, Candidates: cands})
	if !ok || hop == exclude || !slices.Contains(rs.hops, hop) {
		return nil
	}
	if hop != rs.current {
		rs.current, rs.since = hop, now
	}
	nb := n.lookupNeighbor(hop)
	if nb == nil {
		return nil
	}
	l, _ := nb.pick()
	return l
}

// Route reports the next hop the node last relayed packets for dst
// through, and since when.
func (n *Node) Route(dst NodeID) (hop NodeID, since time.Time, ok bool) {
	rs := (*n.routes.Load())[dst]
	if rs == nil {
		return NodeID{}, time.Time{}, false
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.current == (NodeID{}) {
		return NodeID{}, time.Time{}, false
	}
	return rs.current, n.wall(rs.since), true
}

// Counters are what a node did with packets since it started.
type Counters struct {
	Sent      uint64 // packets this node's Binds queued on a link
	Delivered uint64 // packets a WireGuard device took from a Bind
	Forwarded uint64 // packets relayed toward their destination
	// Dropped, by reason.
	NoRoute     uint64 // not for this node, and no route for the destination
	Spoofed     uint64 // relayed for a source this node doesn't know
	HopLimit    uint64 // would have reached the next node with no hops left
	NoPath      uint64 // no link to any next or first hop
	UnknownPeer uint64 // for this node, from a node no Bind has as a peer
	QueueFull   uint64 // a link's send queue or a Bind's receive queue was full
	Malformed   uint64 // not a frame this node understands, or too long for WireGuard
	OtherSpace  uint64 // links refused: their listener put them in another space
	// TooLarge: longer than a WireGuard message may be, or than the
	// network under a link carries (its transport said so), sent or
	// relayed. Overlay MTUs above what the links carry show up here.
	TooLarge    uint64
	WriteFailed uint64 // a link's transport failed to write a packet for another reason
	ReadFailed  uint64 // a link's transport failed a read (a packet lost, the link kept)
}

type counters struct {
	sent, delivered, forwarded                      atomic.Uint64
	noRoute, spoofed, hopLimit, noPath, unknownPeer atomic.Uint64
	queueFull, malformed, otherSpace                atomic.Uint64
	tooLarge, writeFailed, readFailed               atomic.Uint64
}

// Counters returns the node's counters.
func (n *Node) Counters() Counters {
	c := &n.counters
	return Counters{
		Sent: c.sent.Load(), Delivered: c.delivered.Load(), Forwarded: c.forwarded.Load(),
		NoRoute: c.noRoute.Load(), Spoofed: c.spoofed.Load(), HopLimit: c.hopLimit.Load(), NoPath: c.noPath.Load(),
		UnknownPeer: c.unknownPeer.Load(), QueueFull: c.queueFull.Load(), Malformed: c.malformed.Load(),
		OtherSpace: c.otherSpace.Load(), TooLarge: c.tooLarge.Load(), WriteFailed: c.writeFailed.Load(),
		ReadFailed: c.readFailed.Load(),
	}
}

// NeighborStatus is the state of the links to one adjacent node. Status
// holds no network addresses, so it may go into telemetry.
type NeighborStatus struct {
	Node  NodeID
	Up    bool
	UpFor time.Duration
	// UpSince is when it came up (UpFor ago), on the node's clock; zero
	// when down. Compare it with other instants rather than subtracting
	// UpFor from a later clock reading, which moves it by the time
	// between the two.
	UpSince time.Time
	RTT     time.Duration
	Dialed  bool // this node dials it (it is in the table's Links)
	Links   []LinkStatus
}

// LinkStatus is one link to an adjacent node.
type LinkStatus struct {
	Dialed    bool
	Transport string
	// Endpoint is the index of the dialed endpoint in the table's Link;
	// -1 for a link the neighbor dialed.
	Endpoint int
	// Active: the link the neighbor's traffic goes out on.
	Active     bool
	Up         bool
	UpFor      time.Duration
	RTT        time.Duration
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64
	QueueFull  uint64
}

// Neighbors reports every adjacent node the node knows of: each one it
// has or had a link to, and each one it dials without ever getting a link
// (down, with no links) once a dial attempt has failed or it has been
// dialed for DialTimeout. A first dial still waiting for an answer isn't
// listed yet: it gets its chance.
func (n *Node) Neighbors() []NeighborStatus {
	now := n.now()
	n.mu.Lock()
	dialing := make(map[NodeID]*dialLoop, len(n.dials))
	for id, d := range n.dials {
		dialing[id] = d
	}
	n.mu.Unlock()
	n.nmu.RLock()
	nbs := make([]*neighbor, 0, len(n.neighbors))
	for _, nb := range n.neighbors {
		nbs = append(nbs, nb)
	}
	n.nmu.RUnlock()
	out := make([]NeighborStatus, 0, len(nbs)+len(dialing))
	for _, nb := range nbs {
		c := Candidate{Hop: nb.id}
		nb.describe(&c, now)
		_, dialed := dialing[nb.id]
		st := NeighborStatus{Node: nb.id, Up: c.Up, UpFor: c.UpFor, RTT: c.RTT, Dialed: dialed, Links: nb.status(now)}
		if c.Up {
			st.UpSince = n.wall(now - int64(c.UpFor))
		}
		out = append(out, st)
		delete(dialing, nb.id)
	}
	// A dialed node keeps its neighbor once it had a link (pruning spares
	// dialed nodes), so what is left never linked since its dial started.
	for id, d := range dialing {
		if d.failed.Load() || now-d.started >= int64(n.opts.DialTimeout) {
			out = append(out, NeighborStatus{Node: id, Dialed: true})
		}
	}
	slices.SortFunc(out, func(a, b NeighborStatus) int { return bytes.Compare(a.Node[:], b.Node[:]) })
	return out
}
