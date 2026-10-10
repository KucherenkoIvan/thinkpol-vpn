package path

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Options tune liveness, failover and queues. The zero value of a field
// means its default.
type Options struct {
	// ProbeInterval is how often a dialed link is probed when it hasn't
	// both sent and received within it (default 2 s).
	ProbeInterval time.Duration
	// DeadAfter is how long a link may stay silent before it counts as
	// down and is closed; a dialed link is then redialed (default 6 s,
	// three probes).
	DeadAfter time.Duration
	// FollowFor is how long a peer's latest path stays worth following
	// after its last packet (default DeadAfter).
	FollowFor time.Duration
	// RedialMin and RedialMax bound the backoff between dials of one
	// adjacent node (defaults 250 ms and 5 s).
	RedialMin, RedialMax time.Duration
	// HopLimit is what this node's packets start with (default
	// DefaultHopLimit).
	HopLimit uint8
	// QueueLen is each link's send queue, in packets (default 256). A full
	// queue drops.
	QueueLen int
	// Selector picks first hops for peers that don't bring their own
	// (default Failover with a 20 s hold-down).
	Selector Selector
}

func (o Options) withDefaults() Options {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.ProbeInterval, 2*time.Second)
	def(&o.DeadAfter, 3*o.ProbeInterval)
	def(&o.FollowFor, o.DeadAfter)
	def(&o.RedialMin, 250*time.Millisecond)
	def(&o.RedialMax, 5*time.Second)
	if o.HopLimit == 0 {
		o.HopLimit = DefaultHopLimit
	}
	if o.QueueLen <= 0 {
		o.QueueLen = 256
	}
	if o.Selector == nil {
		o.Selector = Failover{HoldDown: 20 * time.Second}
	}
	return o
}

// Table is what a node's map section says about adjacency and forwarding.
// The engine builds it from the section (see package dataplane).
type Table struct {
	// Links are the adjacent nodes this node dials. Adjacent nodes that
	// dial this node arrive through Serve instead.
	Links []Link
	// Routes are the forwarding table. A node forwards a packet that isn't
	// addressed to it only along a route for its destination; nothing else
	// is relayed.
	Routes []Route
}

// Link is an adjacent node this node keeps a link to.
type Link struct {
	Node NodeID
	// Endpoints are the ways to reach it, in priority order.
	Endpoints []Endpoint
}

// Endpoint is one way to dial an adjacent node: a transport's dialer, the
// address, and what the map says about the link.
type Endpoint struct {
	Dialer  transport.Dialer
	Address string
	Config  transport.DialConfig
}

// Route sends packets for Destination through one of NextHops, adjacent
// nodes in priority order; the next hop may be the destination itself.
type Route struct {
	Destination NodeID
	NextHops    []NodeID
}

// ErrClosed is returned once the node is closed.
var ErrClosed = errors.New("path: node closed")

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

	mu    sync.Mutex
	dials map[NodeID]*dialLoop
	binds map[*Bind]struct{}

	nmu       sync.RWMutex
	neighbors map[NodeID]*neighbor

	routes atomic.Pointer[map[NodeID][]NodeID]
	peers  atomic.Pointer[map[NodeID]*peerState] // every Bind's peers

	counters counters
}

// NewNode starts the path layer of node id. Give it a Table with Update and
// its listeners with Serve.
func NewNode(id NodeID, opts Options) *Node {
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		id: id, opts: opts.withDefaults(), start: time.Now(),
		ctx: ctx, cancel: cancel,
		dials:     make(map[NodeID]*dialLoop),
		binds:     make(map[*Bind]struct{}),
		neighbors: make(map[NodeID]*neighbor),
	}
	n.routes.Store(&map[NodeID][]NodeID{})
	n.peers.Store(&map[NodeID]*peerState{})
	n.spawn(n.watch)
	return n
}

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

// ID is the node's id.
func (n *Node) ID() NodeID { return n.id }

// now is monotonic nanoseconds since the node started, never zero, which
// means "never" in the timestamps below.
func (n *Node) now() int64 { return int64(time.Since(n.start)) + 1 }

// Update replaces the node's table. Links whose endpoints didn't change
// carry on; the rest are closed and dialed anew. Entries naming no node,
// the node itself, or nowhere to go are skipped: the map's reader doesn't
// rule them out.
func (n *Node) Update(t Table) {
	routes := make(map[NodeID][]NodeID, len(t.Routes))
	for _, r := range t.Routes {
		if r.Destination == (NodeID{}) || r.Destination == n.id {
			continue
		}
		var hops []NodeID
		for _, h := range r.NextHops {
			if h != (NodeID{}) && h != n.id && !slices.Contains(hops, h) {
				hops = append(hops, h)
			}
		}
		if len(hops) > 0 && routes[r.Destination] == nil {
			routes[r.Destination] = hops
		}
	}
	n.routes.Store(&routes)

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
	for id, d := range n.dials {
		if eps, ok := want[id]; !ok || !sameEndpoints(d.endpoints, eps) {
			d.stop()
			delete(n.dials, id)
		}
	}
	for id, eps := range want {
		if _, ok := n.dials[id]; !ok {
			n.dials[id] = n.startDial(n.neighbor(id), eps)
		}
	}
}

func sameEndpoints(a, b []Endpoint) bool {
	return slices.EqualFunc(a, b, func(x, y Endpoint) bool {
		return x.Dialer == y.Dialer && x.Address == y.Address &&
			bytes.Equal(x.Config.Credential, y.Config.Credential) &&
			bytes.Equal(x.Config.Settings, y.Config.Settings) &&
			x.Config.Shaping == y.Config.Shaping
	})
}

// Serve accepts links from l until l or the node is closed, and returns
// nil when the node closed first. Each accepted link belongs to the
// adjacent node the listener authenticated.
func (n *Node) Serve(l transport.Listener) error {
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
		if peer.Node == (NodeID{}) || peer.Node == n.id {
			_ = tl.Close()
			continue
		}
		n.addLink(n.neighbor(peer.Node), tl, false)
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
			l.close()
		}
	}
	n.nmu.RUnlock()
	n.wg.Wait()
	return nil
}

func (n *Node) neighbor(id NodeID) *neighbor {
	n.nmu.RLock()
	nb := n.neighbors[id]
	n.nmu.RUnlock()
	if nb != nil {
		return nb
	}
	n.nmu.Lock()
	defer n.nmu.Unlock()
	if nb = n.neighbors[id]; nb == nil {
		nb = &neighbor{id: id}
		n.neighbors[id] = nb
	}
	return nb
}

func (n *Node) lookupNeighbor(id NodeID) *neighbor {
	n.nmu.RLock()
	defer n.nmu.RUnlock()
	return n.neighbors[id]
}

// watch closes links that went silent and probes dialed links.
func (n *Node) watch() {
	tick := time.NewTicker(max(n.opts.ProbeInterval/4, 5*time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
		now := n.now()
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
			l.send(b)
			return
		}
	case kindProbeReply:
		if len(f) == probeSize {
			l.probeReply(f, n.now())
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
	ps.bind.deliver(ps, via, b, n.now())
}

// forward relays a packet along this node's route for its destination,
// never back to the neighbor it came from.
func (n *Node) forward(from *link, h header, b *[]byte) {
	hops := (*n.routes.Load())[h.dst]
	switch {
	case hops == nil:
		n.counters.noRoute.Add(1)
	case h.hopLimit <= 1:
		n.counters.hopLimit.Add(1)
	default:
		now := n.now()
		var to, fallback *link
		for _, id := range hops {
			nb := n.lookupNeighbor(id)
			if id == from.nb.id || nb == nil {
				continue
			}
			best, up := nb.pick(now)
			if up {
				to = best
				break
			}
			if fallback == nil {
				fallback = best
			}
		}
		if to == nil {
			to = fallback
		}
		if to == nil {
			n.counters.noPath.Add(1)
			break
		}
		(*b)[1] = h.hopLimit - 1
		if to.send(b) {
			n.counters.forwarded.Add(1)
		}
		return
	}
	putBuf(b)
}

// Counters are what a node did with packets since it started.
type Counters struct {
	Sent      uint64 // packets this node's Binds sent
	Delivered uint64 // packets handed to a Bind
	Forwarded uint64 // packets relayed toward their destination
	// Dropped, by reason.
	NoRoute     uint64 // not for this node, and no route for the destination
	HopLimit    uint64 // would have reached the next node with no hops left
	NoPath      uint64 // no link to any next or first hop
	UnknownPeer uint64 // for this node, from a node no Bind has as a peer
	QueueFull   uint64 // a link's send queue or a Bind's receive queue was full
	Malformed   uint64 // not a frame this node understands
}

type counters struct {
	sent, delivered, forwarded                        atomic.Uint64
	noRoute, hopLimit, noPath, unknownPeer, queueFull atomic.Uint64
	malformed                                         atomic.Uint64
}

// Counters returns the node's counters.
func (n *Node) Counters() Counters {
	c := &n.counters
	return Counters{
		Sent: c.sent.Load(), Delivered: c.delivered.Load(), Forwarded: c.forwarded.Load(),
		NoRoute: c.noRoute.Load(), HopLimit: c.hopLimit.Load(), NoPath: c.noPath.Load(),
		UnknownPeer: c.unknownPeer.Load(), QueueFull: c.queueFull.Load(), Malformed: c.malformed.Load(),
	}
}

// NeighborStatus is the state of the links to one adjacent node.
type NeighborStatus struct {
	Node   NodeID
	Links  int
	Up     bool
	UpFor  time.Duration
	RTT    time.Duration
	Dialed bool // this node dials it (it is in the table's Links)
}

// Neighbors reports every adjacent node the node has heard of.
func (n *Node) Neighbors() []NeighborStatus {
	now := n.now()
	n.mu.Lock()
	dialed := make(map[NodeID]bool, len(n.dials))
	for id := range n.dials {
		dialed[id] = true
	}
	n.mu.Unlock()
	n.nmu.RLock()
	defer n.nmu.RUnlock()
	out := make([]NeighborStatus, 0, len(n.neighbors))
	for id, nb := range n.neighbors {
		c := nb.candidate(now)
		out = append(out, NeighborStatus{
			Node: id, Links: len(nb.all()), Up: c.Up, UpFor: c.UpFor, RTT: c.RTT, Dialed: dialed[id],
		})
	}
	slices.SortFunc(out, func(a, b NeighborStatus) int { return bytes.Compare(a.Node[:], b.Node[:]) })
	return out
}
