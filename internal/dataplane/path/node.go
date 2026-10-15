package path

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Options tune liveness, failover and queues. The zero value of a field
// means its default.
type Options struct {
	// ProbeInterval is how often each end probes a link whose last proof
	// is older than that (default 2 s).
	ProbeInterval time.Duration
	// DeadAfter is how long a link may go without a reply to its probes
	// before it counts as down and is closed; a dialed link is then
	// redialed (default three probe intervals). It must exceed
	// ProbeInterval, and should leave room for both ends' shaping delays
	// and twice transport.MaxControlHold on links that shape.
	DeadAfter time.Duration
	// FollowFor is how long the leader's latest path stays worth following
	// after its last packet (default DeadAfter).
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
	// only ever subtracts its readings. Timers that only pace the work (the
	// liveness check, dial backoff) stay on the wall clock.
	Now func() time.Time
	// Log gets the links' lives at info level: up, closed and why, the
	// first failed dial of a run and the first failed read or write of a
	// link (the rest at debug). Nil discards them.
	Log *slog.Logger

	watchEvery time.Duration // how often links are checked (tests)
}

func (o Options) withDefaults() (Options, error) {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.ProbeInterval, 2*time.Second)
	def(&o.DeadAfter, 3*o.ProbeInterval)
	def(&o.FollowFor, o.DeadAfter)
	def(&o.RedialMin, 250*time.Millisecond)
	def(&o.RedialMax, max(5*time.Second, o.RedialMin))
	def(&o.watchEvery, max(o.ProbeInterval/4, 5*time.Millisecond))
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
	switch {
	case o.DeadAfter <= o.ProbeInterval:
		return o, fmt.Errorf("path: DeadAfter %v must exceed ProbeInterval %v", o.DeadAfter, o.ProbeInterval)
	case o.RedialMax < o.RedialMin:
		return o, fmt.Errorf("path: RedialMax %v is below RedialMin %v", o.RedialMax, o.RedialMin)
	}
	return o, nil
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
			n.addLink(peer.Node, tl, false, transportName, -1)
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

// watch closes links that went silent, probes dialed links, and now and
// then forgets adjacent nodes no longer used.
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
		if now-pruned >= int64(n.opts.DeadAfter) {
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
				l.tick(now)
			}
		}
	}
}

// handle takes one frame read from l and owns b from then on.
func (n *Node) handle(l *link, b *[]byte) {
	f := *b
	switch f[0] {
	case kindProbe:
		if len(f) == probeSize {
			f[0] = kindProbeReply
			l.sendControl(b)
			return
		}
	case kindProbeReply:
		if len(f) == probeSize {
			l.probeReply(f, n.now())
			putBuf(b)
			return
		}
	case kindPacket:
		h, ok := parsePacket(f)
		switch {
		case !ok:
		case h.dst == n.id:
			n.deliver(h.src, l.nb.id, b)
			return
		default:
			n.forward(l, h, b)
			return
		}
	}
	n.counters.malformed.Add(1)
	putBuf(b)
}

func (n *Node) deliver(src, via NodeID, b *[]byte) {
	ps := (*n.peers.Load())[src]
	if ps == nil {
		n.counters.unknownPeer.Add(1)
		putBuf(b)
		return
	}
	ps.bind.Load().deliver(ps, via, b, n.now())
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
		to := rs.pick(n, from.nb.id, n.now())
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
func (rs *routeState) pick(n *Node, exclude NodeID, now int64) *link {
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
	l, _ := nb.pick(now)
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
	// StaleClock is what the links' transports dropped as sealed outside
	// their clock margin (udp: five minutes): a peer's clock disagrees
	// with the node's beyond the margin. When the last was seen is
	// StaleClockSeen.
	StaleClock uint64
}

type counters struct {
	sent, delivered, forwarded                      atomic.Uint64
	noRoute, spoofed, hopLimit, noPath, unknownPeer atomic.Uint64
	queueFull, malformed, otherSpace                atomic.Uint64
	tooLarge, writeFailed, readFailed               atomic.Uint64
	// staleClock is what the links' transports dropped as sealed outside
	// their clock margin; staleClockAt is when the last was seen, on the
	// node's clock (0: never).
	staleClock   atomic.Uint64
	staleClockAt atomic.Int64
}

// Counters returns the node's counters.
func (n *Node) Counters() Counters {
	c := &n.counters
	return Counters{
		Sent: c.sent.Load(), Delivered: c.delivered.Load(), Forwarded: c.forwarded.Load(),
		NoRoute: c.noRoute.Load(), Spoofed: c.spoofed.Load(), HopLimit: c.hopLimit.Load(), NoPath: c.noPath.Load(),
		UnknownPeer: c.unknownPeer.Load(), QueueFull: c.queueFull.Load(), Malformed: c.malformed.Load(),
		OtherSpace: c.otherSpace.Load(), TooLarge: c.tooLarge.Load(), WriteFailed: c.writeFailed.Load(),
		ReadFailed: c.readFailed.Load(), StaleClock: c.staleClock.Load(),
	}
}

// StaleClockSeen is when the node last saw a link's transport drop a
// datagram as sealed outside its clock margin; zero if never.
func (n *Node) StaleClockSeen() time.Time {
	if t := n.counters.staleClockAt.Load(); t != 0 {
		return n.wall(t)
	}
	return time.Time{}
}

// NeighborStatus is the state of the links to one adjacent node. Status
// holds no network addresses, so it may go into telemetry.
type NeighborStatus struct {
	Node   NodeID
	Up     bool
	UpFor  time.Duration
	RTT    time.Duration
	Dialed bool // this node dials it (it is in the table's Links)
	Links  []LinkStatus
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

// Neighbors reports every adjacent node the node knows of.
func (n *Node) Neighbors() []NeighborStatus {
	now := n.now()
	n.mu.Lock()
	dialed := make(map[NodeID]bool, len(n.dials))
	for id := range n.dials {
		dialed[id] = true
	}
	n.mu.Unlock()
	n.nmu.RLock()
	nbs := make([]*neighbor, 0, len(n.neighbors))
	for _, nb := range n.neighbors {
		nbs = append(nbs, nb)
	}
	n.nmu.RUnlock()
	out := make([]NeighborStatus, 0, len(nbs))
	for _, nb := range nbs {
		c := Candidate{Hop: nb.id}
		nb.describe(&c, now)
		out = append(out, NeighborStatus{
			Node: nb.id, Up: c.Up, UpFor: c.UpFor, RTT: c.RTT, Dialed: dialed[nb.id], Links: nb.status(now),
		})
	}
	slices.SortFunc(out, func(a, b NeighborStatus) int { return bytes.Compare(a.Node[:], b.Node[:]) })
	return out
}
