package path

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
)

// Peer is one of a WireGuard device's peers, as the path layer sees it.
type Peer struct {
	ID NodeID
	// FirstHops are the candidate first hops in priority order: adjacent
	// nodes that route the rest of the way, or the peer itself when it is
	// adjacent.
	FirstHops []NodeID
	// Selector picks among them; nil means the node's.
	Selector Selector
}

var (
	// ErrUnknownPeer: Send was given an endpoint of no peer of this Bind.
	ErrUnknownPeer = errors.New("path: not a peer of this bind")
	// ErrNoPath: no candidate first hop of the peer has a link.
	ErrNoPath = errors.New("path: no path to the peer")
	// ErrPeerTaken: another Bind of the node already has the peer.
	ErrPeerTaken = errors.New("path: peer belongs to another bind")
	// ErrMessageSize: a message is empty or larger than MaxMessageSize.
	ErrMessageSize = errors.New("path: message size out of range")
)

// bindBatch is how many messages WireGuard hands a Bind at once. wireguard-go
// keeps a buffer of 64 KiB per message of a batch, per receive routine.
const bindBatch = 16

// Bind is a WireGuard device's conn.Bind on top of a Node. WireGuard sees
// one stable endpoint per peer, named by the peer's node id
// (ParseEndpoint takes it in hex); underneath, each packet leaves through
// one of the peer's candidate first hops, as its Selector picks, so
// switching paths never touches WireGuard's session. The Bind opens no
// socket: everything goes over the node's transport links.
//
// The endpoints a Bind hands WireGuard with received packets also carry
// the first hop they came through. WireGuard adopts an endpoint only from
// a packet it authenticated, so the endpoint it sends to tells the Bind
// which path the peer is using; the Selector may follow it.
type Bind struct {
	node  *Node
	in    chan inbound
	peers atomic.Pointer[map[NodeID]*peerState] // written under node.mu

	mu     sync.Mutex
	open   chan struct{} // closed by Close; nil while closed
	isOpen atomic.Bool
}

var _ conn.Bind = (*Bind)(nil)

type inbound struct {
	buf *[]byte // a packet frame
	ep  *peerEndpoint
}

// NewBind returns a Bind for one WireGuard device; give it the device's
// peers with SetPeers.
func (n *Node) NewBind() *Bind {
	b := &Bind{node: n, in: make(chan inbound, 1024)}
	b.peers.Store(&map[NodeID]*peerState{})
	n.mu.Lock()
	n.binds[b] = struct{}{}
	n.mu.Unlock()
	return b
}

// SetPeers replaces the Bind's peers. A peer keeps its path state across
// calls. Peers and first hops naming no node or this node are skipped. It
// fails, changing nothing, if another Bind of the node has one of the
// peers: a peer belongs to one WireGuard device.
func (b *Bind) SetPeers(peers []Peer) error {
	n := b.node
	n.mu.Lock()
	defer n.mu.Unlock()
	old := *b.peers.Load()
	next := make(map[NodeID]*peerState, len(peers))
	for _, p := range peers {
		if p.ID == (NodeID{}) || p.ID == n.id {
			continue
		}
		for other := range n.binds {
			if other != b && (*other.peers.Load())[p.ID] != nil {
				return fmt.Errorf("%w: %s", ErrPeerTaken, p.ID)
			}
		}
		var hops []NodeID
		for _, h := range p.FirstHops {
			if h != (NodeID{}) && h != n.id && !slices.Contains(hops, h) {
				hops = append(hops, h)
			}
		}
		ps := old[p.ID]
		if ps == nil {
			ps = &peerState{id: p.ID, bind: b}
		}
		ps.mu.Lock()
		ps.hops, ps.selector = hops, p.Selector
		ps.mu.Unlock()
		next[p.ID] = ps
	}
	b.peers.Store(&next)
	all := make(map[NodeID]*peerState)
	for bb := range n.binds {
		for id, ps := range *bb.peers.Load() {
			all[id] = ps
		}
	}
	n.peers.Store(&all)
	return nil
}

// Current reports the first hop the Bind last sent to peer through.
func (b *Bind) Current(peer NodeID) (NodeID, bool) {
	ps := (*b.peers.Load())[peer]
	if ps == nil {
		return NodeID{}, false
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.current, ps.current != (NodeID{})
}

// Open implements conn.Bind. There is no port: it reports 0.
func (b *Bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	open := make(chan struct{})
	b.open = open
	b.isOpen.Store(true)
	return []conn.ReceiveFunc{b.receiveFunc(open)}, 0, nil
}

// Close implements conn.Bind. Packets arriving while closed are dropped.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open == nil {
		return nil
	}
	b.isOpen.Store(false)
	close(b.open)
	b.open = nil
	for {
		select {
		case in := <-b.in:
			putBuf(in.buf)
		default:
			return nil
		}
	}
}

func (b *Bind) receiveFunc(open chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			select {
			case <-open:
				return 0, net.ErrClosed
			default:
			}
			var in inbound
			select {
			case <-open:
				return 0, net.ErrClosed
			case in = <-b.in:
			}
			n := 0
			for {
				if m := (*in.buf)[HeaderSize:]; len(m) <= len(packets[n]) {
					sizes[n] = copy(packets[n], m)
					eps[n] = in.ep
					n++
				}
				putBuf(in.buf)
				if n == len(packets) {
					return n, nil
				}
				select {
				case in = <-b.in:
					continue
				default:
				}
				break
			}
			if n > 0 {
				return n, nil
			}
		}
	}
}

func (b *Bind) deliver(ps *peerState, via NodeID, buf *[]byte, now int64) {
	c := &b.node.counters
	if !b.isOpen.Load() { // the device is down
		putBuf(buf)
		return
	}
	ep := ps.endpoint(via)
	ep.lastSeen.Store(now)
	select {
	case b.in <- inbound{buf: buf, ep: ep}:
		c.delivered.Add(1)
	default:
		c.queueFull.Add(1)
		putBuf(buf)
	}
}

// Send implements conn.Bind: every message goes to ep's peer through the
// first hop its Selector picks.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	pe, ok := ep.(*peerEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	n := b.node
	ps := (*b.peers.Load())[pe.peer]
	if ps == nil {
		return fmt.Errorf("%w: %s", ErrUnknownPeer, pe.peer)
	}
	l := ps.route(n, pe)
	if l == nil {
		n.counters.noPath.Add(uint64(len(bufs)))
		return fmt.Errorf("%w: %s", ErrNoPath, pe.peer)
	}
	h := header{hopLimit: n.opts.HopLimit, dst: pe.peer, src: n.id}
	var err error
	for _, m := range bufs {
		if len(m) == 0 || len(m) > MaxMessageSize {
			err = fmt.Errorf("%w: %d bytes", ErrMessageSize, len(m))
			continue
		}
		fb := getBuf()
		f := (*fb)[:HeaderSize+len(m)]
		putHeader(f, h)
		copy(f[HeaderSize:], m)
		*fb = f
		if l.send(fb) {
			n.counters.sent.Add(1)
		}
	}
	return err
}

// SetMark implements conn.Bind. Links carry their own socket options (see
// the transport adapters), so there is nothing to mark here.
func (b *Bind) SetMark(uint32) error { return nil }

// BatchSize implements conn.Bind.
func (b *Bind) BatchSize() int { return bindBatch }

// ParseEndpoint implements conn.Bind: an endpoint is a peer's node id in
// hex. Network addresses are refused; WireGuard never gets to name one.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(NodeID{}) {
		return nil, fmt.Errorf("path: endpoint %q is not a node id", s)
	}
	var id NodeID
	copy(id[:], raw)
	if id == (NodeID{}) {
		return nil, fmt.Errorf("path: endpoint %q is the zero node id", s)
	}
	return &peerEndpoint{peer: id}, nil
}

// peerState is one peer's paths and the endpoints handed to WireGuard.
type peerState struct {
	id   NodeID
	bind *Bind

	mu       sync.Mutex
	hops     []NodeID
	selector Selector
	current  NodeID
	cands    []Candidate // scratch for route

	eps sync.Map // via NodeID → *peerEndpoint
}

func (ps *peerState) endpoint(via NodeID) *peerEndpoint {
	if ep, ok := ps.eps.Load(via); ok {
		return ep.(*peerEndpoint)
	}
	ep, _ := ps.eps.LoadOrStore(via, &peerEndpoint{peer: ps.id, via: via})
	return ep.(*peerEndpoint)
}

// route picks the peer's first hop and the link to send on.
func (ps *peerState) route(n *Node, pe *peerEndpoint) *link {
	now := n.now()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	cands := ps.cands[:0]
	followed := pe.via != (NodeID{}) && now-pe.lastSeen.Load() < int64(n.opts.FollowFor)
	for _, h := range ps.hops {
		c := Candidate{Hop: h}
		if nb := n.lookupNeighbor(h); nb != nil {
			c = nb.candidate(now)
		}
		c.Followed = followed && h == pe.via
		cands = append(cands, c)
	}
	ps.cands = cands
	sel := ps.selector
	if sel == nil {
		sel = n.opts.Selector
	}
	hop, ok := sel.Select(ps.current, cands)
	if !ok || !slices.Contains(ps.hops, hop) {
		return nil
	}
	ps.current = hop
	nb := n.lookupNeighbor(hop)
	if nb == nil {
		return nil
	}
	l, _ := nb.pick(now)
	return l
}

// peerEndpoint is what WireGuard holds for a peer: the peer's node id, and
// the first hop the packet it came with arrived through (zero for an
// endpoint from ParseEndpoint). WireGuard sees the same address for every
// path to a peer.
type peerEndpoint struct {
	peer, via NodeID
	lastSeen  atomic.Int64 // node time of the last packet through via
}

func (e *peerEndpoint) ClearSrc()           {}
func (e *peerEndpoint) SrcToString() string { return "" }
func (e *peerEndpoint) DstToString() string { return e.peer.String() }

// DstToBytes keys WireGuard's cookies (mac2), so it is the same for every
// path to the peer.
func (e *peerEndpoint) DstToBytes() []byte { return slices.Clone(e.peer[:]) }

// DstIP keys WireGuard's handshake rate limiter. It is a stand-in address
// per peer in the IPv6 discard-only prefix 100::/64 (RFC 6666), never
// dialed or routed.
func (e *peerEndpoint) DstIP() netip.Addr {
	var a [16]byte
	a[0] = 0x01
	copy(a[8:], e.peer[:])
	return netip.AddrFrom16(a)
}

func (e *peerEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
