package path

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Peer is one of a WireGuard device's peers, as the path layer sees it.
type Peer struct {
	ID NodeID
	// FirstHops are the candidate first hops in priority order: adjacent
	// nodes that route the rest of the way, or the peer itself when it is
	// adjacent.
	FirstHops []NodeID
	// Selector picks among them; nil means the node's. Its state, if any,
	// is its own: pass the same value again to keep it.
	Selector Selector
}

var (
	// ErrUnknownPeer: Send was given an endpoint of no peer of this Bind.
	ErrUnknownPeer = errors.New("path: not a peer of this bind")
	// ErrNoPath: no candidate first hop of the peer has a link.
	ErrNoPath = errors.New("path: no path to the peer")
	// ErrPeerTaken: another Bind of the node has the peer.
	ErrPeerTaken = errors.New("path: peer belongs to another bind")
	// ErrMessageSize: a message is empty or larger than MaxMessageSize.
	ErrMessageSize = errors.New("path: message size out of range")
	// ErrReleased: the Bind was released from its node.
	ErrReleased = errors.New("path: bind released")
	// ErrNoSocket: SetMark with a mark. A Bind has no socket to mark;
	// links' sockets are marked by their transport adapters.
	ErrNoSocket = errors.New("path: a bind has no socket to mark")
)

// bindBatch is how many messages WireGuard hands a Bind at once. wireguard-go
// keeps a buffer of 64 KiB per message of a batch, per receive routine.
const bindBatch = 16

// wireguardKeepalive is WireGuard's keepalive timeout: a peer that only
// receives data answers with a keepalive this long after.
const wireguardKeepalive = 10 * time.Second

// Bind is a WireGuard device's conn.Bind on top of a Node. WireGuard sees
// one stable endpoint per peer, named by the peer's node id
// (ParseEndpoint takes it in hex); underneath, each batch leaves through
// one of the peer's candidate first hops, as its Selector picks, so
// switching paths never touches WireGuard's session. The Bind opens no
// socket: everything goes over the node's transport links.
//
// The endpoints a Bind hands WireGuard with received packets also carry
// the first hop they came through. WireGuard adopts an endpoint only from
// a packet it authenticated, so the endpoint it sends to tells the Bind
// which path the peer is using; the end of a pair with the higher node id
// follows it.
//
// A first hop whose links are up can still lead nowhere further on. As a
// stopgap until paths are probed end to end, a Bind that keeps sending a
// peer through one first hop with nothing coming back demotes that hop for
// the peer (Options.E2EDead). For the leading end of a pair, only what
// comes back through that hop counts: a follower that talks through
// another hop can't be reached through this one.
type Bind struct {
	node  *Node
	in    chan inbound
	peers atomic.Pointer[map[NodeID]*peerState] // written under node.mu

	released bool // under node.mu

	rmu  sync.RWMutex  // Open and Close against deliver
	open chan struct{} // closed by Close; nil while closed
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

// SetPeers replaces the Bind's peers; see Node.SetPeers.
func (b *Bind) SetPeers(peers []Peer) error {
	return b.node.SetPeers(map[*Bind][]Peer{b: peers})
}

// SetPeers replaces the peers of several Binds at once, so a peer can move
// from one Bind to another in one step. A peer belongs to one Bind: it
// fails, changing nothing, if two Binds would have the same peer. A peer
// that stays in its Bind keeps its path state; a moved peer starts afresh.
// Peers and first hops naming no node or this node are skipped.
func (n *Node) SetPeers(set map[*Bind][]Peer) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	owner := make(map[NodeID]*Bind)
	for b := range n.binds {
		if _, replaced := set[b]; !replaced {
			for id := range *b.peers.Load() {
				owner[id] = b
			}
		}
	}
	for b, peers := range set {
		switch {
		case b.node != n:
			return errors.New("path: bind of another node")
		case b.released:
			return ErrReleased
		}
		for _, p := range peers {
			if p.ID == (NodeID{}) || p.ID == n.id {
				continue
			}
			if o := owner[p.ID]; o != nil && o != b {
				return fmt.Errorf("%w: %s", ErrPeerTaken, p.ID)
			}
			owner[p.ID] = b
		}
	}
	for b, peers := range set {
		old := *b.peers.Load()
		next := make(map[NodeID]*peerState, len(peers))
		for _, p := range peers {
			if p.ID == (NodeID{}) || p.ID == n.id {
				continue
			}
			ps := old[p.ID]
			if ps == nil {
				ps = &peerState{id: p.ID, follows: bytes.Compare(n.id[:], p.ID[:]) > 0}
				ps.bind.Store(b)
			}
			hops := n.cleanHops(p.FirstHops)
			ps.hops.Store(&hops)
			ps.mu.Lock()
			ps.selector = p.Selector
			ps.mu.Unlock()
			next[p.ID] = ps
		}
		b.peers.Store(&next)
	}
	n.indexPeersLocked()
	return nil
}

func (n *Node) indexPeersLocked() {
	all := make(map[NodeID]*peerState)
	for b := range n.binds {
		for id, ps := range *b.peers.Load() {
			all[id] = ps
		}
	}
	n.peers.Store(&all)
}

// Release takes the Bind off its node: its peers are freed for other
// Binds, and nothing more is delivered to it. Close it (its WireGuard
// device does) as well.
func (b *Bind) Release() {
	n := b.node
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.binds, b)
	b.released = true
	b.peers.Store(&map[NodeID]*peerState{})
	n.indexPeersLocked()
}

// Current reports the first hop the Bind sends to peer through, and since
// when.
func (b *Bind) Current(peer NodeID) (hop NodeID, since time.Time, ok bool) {
	ps := (*b.peers.Load())[peer]
	if ps == nil {
		return NodeID{}, time.Time{}, false
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.current == (NodeID{}) {
		return NodeID{}, time.Time{}, false
	}
	return ps.current, b.node.wall(ps.since), true
}

// Open implements conn.Bind. There is no port: it reports 0.
func (b *Bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	if b.open != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	open := make(chan struct{})
	b.open = open
	return []conn.ReceiveFunc{b.receiveFunc(open)}, 0, nil
}

// Close implements conn.Bind. Packets arriving while closed are dropped.
func (b *Bind) Close() error {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	if b.open == nil {
		return nil
	}
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
	c := &b.node.counters
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
					c.delivered.Add(1)
				} else {
					c.malformed.Add(1)
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

// deliver queues a packet from ps that arrived through via, a neighbor that
// must be one of the peer's first hops (a reverse-path check).
func (b *Bind) deliver(ps *peerState, via NodeID, buf *[]byte, now int64) {
	c := &b.node.counters
	if !slices.Contains(*ps.hops.Load(), via) {
		c.spoofed.Add(1)
		putBuf(buf)
		return
	}
	b.rmu.RLock()
	defer b.rmu.RUnlock()
	if b.open == nil { // the device is down
		putBuf(buf)
		return
	}
	ep := ps.endpoint(via)
	// Cookie replies and junk don't count as a sign of the peer's life.
	if t := wgType((*buf)[HeaderSize:]); t != 0 && t != wgCookie {
		ep.lastSeen.Store(now)
		ps.heard(via)
	}
	select {
	case b.in <- inbound{buf: buf, ep: ep}:
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
	initiation, cookies := false, true
	for _, m := range bufs {
		switch wgType(m) {
		case wgInitiation:
			initiation, cookies = true, false
		case wgCookie:
		default:
			cookies = false
		}
	}
	l := ps.route(n, pe, initiation, cookies)
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

// SetMark implements conn.Bind. Never mark WireGuard's device: links'
// sockets are marked by their transport adapters (udp.Options.Control).
func (b *Bind) SetMark(mark uint32) error {
	if mark != 0 {
		return ErrNoSocket
	}
	return nil
}

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
	id      NodeID
	follows bool // this node's id is the higher of the pair
	bind    atomic.Pointer[Bind]
	hops    atomic.Pointer[[]NodeID]

	mu       sync.Mutex
	selector Selector
	current  NodeID
	since    int64
	// Sending through current with nothing delivered from the peer since:
	// anything, and handshake initiations.
	sendingSince, initiationSince int64
	demoted                       map[NodeID]demotion
	cands                         []Candidate // scratch for route

	eps sync.Map // via NodeID → *peerEndpoint
}

// demotion is a first hop the Bind found leads nowhere for the peer.
type demotion struct {
	at, until int64
	count     int
}

func (ps *peerState) endpoint(via NodeID) *peerEndpoint {
	if ep, ok := ps.eps.Load(via); ok {
		return ep.(*peerEndpoint)
	}
	ep, _ := ps.eps.LoadOrStore(via, &peerEndpoint{peer: ps.id, via: via})
	return ep.(*peerEndpoint)
}

// heard records that something came from the peer through via. It answers
// what this end sent if this end follows (it sends the way the peer's
// packets come), or if it came through the hop this end sends on: a leader
// whose follower talks through another hop isn't getting through its own.
func (ps *peerState) heard(via NodeID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.follows || via == ps.current {
		ps.sendingSince, ps.initiationSince = 0, 0
	}
}

// talkingElsewhere: the peer's packets came through a hop other than
// current within d.
func (ps *peerState) talkingElsewhere(current NodeID, now int64, d time.Duration) bool {
	elsewhere := false
	ps.eps.Range(func(k, v any) bool {
		seen := v.(*peerEndpoint).lastSeen.Load()
		if k.(NodeID) != current && seen != 0 && now-seen < int64(d) {
			elsewhere = true
		}
		return !elsewhere
	})
	return elsewhere
}

const demotionMemory = int64(10 * time.Minute)

// route picks the peer's first hop and the link to send on. Cookie replies
// go out without touching the peer's state: WireGuard sends them to the
// endpoint of a packet it couldn't yet authenticate.
func (ps *peerState) route(n *Node, pe *peerEndpoint, initiation, cookies bool) *link {
	now := n.now()
	o := &n.opts
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if cur := ps.current; cur != (NodeID{}) && !cookies {
		unanswered := func(since int64, d time.Duration) bool { return since != 0 && now-since > int64(d) }
		if unanswered(ps.initiationSince, o.E2EDead) ||
			unanswered(ps.sendingSince, o.E2EDead+wireguardKeepalive) ||
			!ps.follows && unanswered(ps.sendingSince, o.E2EDead) && ps.talkingElsewhere(cur, now, o.E2EDead) {
			ps.demote(cur, now, o.E2EDead)
			n.counters.demotions.Add(1)
		}
	}
	hops := *ps.hops.Load()
	follow := ps.follows && !cookies && pe.via != (NodeID{}) && now-pe.lastSeen.Load() < int64(o.FollowFor)
	cands := ps.cands[:0]
	for _, h := range hops {
		c := n.candidate(h, now)
		if d, ok := ps.demoted[h]; ok {
			switch {
			case now < d.until:
				c.Up, c.UpFor = false, 0
			case c.Up:
				c.UpFor = min(c.UpFor, time.Duration(now-d.until))
			}
		}
		if v, ok := ps.eps.Load(h); ok {
			if seen := v.(*peerEndpoint).lastSeen.Load(); seen != 0 {
				c.HeardVia = time.Duration(now - seen)
			}
		}
		c.Followed = follow && h == pe.via
		cands = append(cands, c)
	}
	ps.cands = cands
	sel := ps.selector
	if sel == nil {
		sel = o.Selector
	}
	hop, ok := sel.Select(ps.current, cands)
	if !ok || !slices.Contains(hops, hop) {
		return nil
	}
	if !cookies {
		if hop != ps.current {
			ps.current, ps.since = hop, now
			ps.sendingSince, ps.initiationSince = 0, 0
		}
		if ps.sendingSince == 0 {
			ps.sendingSince = now
		}
		if initiation && ps.initiationSince == 0 {
			ps.initiationSince = now
		}
	}
	nb := n.lookupNeighbor(hop)
	if nb == nil {
		return nil
	}
	l, _ := nb.pick(now)
	return l
}

// demote treats hop as down for the peer for e2eDead, twice as long each
// time it is demoted again within demotionMemory.
func (ps *peerState) demote(hop NodeID, now int64, e2eDead time.Duration) {
	if ps.demoted == nil {
		ps.demoted = make(map[NodeID]demotion)
	}
	d := ps.demoted[hop]
	if d.count > 0 && now-d.at < demotionMemory {
		d.count++
	} else {
		d.count = 1
	}
	d.at = now
	d.until = now + int64(e2eDead)<<min(d.count-1, 6)
	ps.demoted[hop] = d
	ps.sendingSince, ps.initiationSince = 0, 0
}

// peerEndpoint is what WireGuard holds for a peer: the peer's node id, and
// the first hop the packet it came with arrived through (zero for an
// endpoint from ParseEndpoint). WireGuard sees the same address for every
// path to a peer.
type peerEndpoint struct {
	peer, via NodeID
	// lastSeen is the node time of the last WireGuard-shaped message, not
	// a cookie reply, from the peer through via.
	lastSeen atomic.Int64
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
