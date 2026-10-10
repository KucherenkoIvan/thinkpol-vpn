// Package memory is an in-process transport: links between listeners and
// dialers of one Network, with no sockets. A network behaves like a datagram
// transport or like a stream transport (Semantics), so the layers above can
// be tested against both; either way it passes the conformance suite and
// nothing answers a bad credential.
//
// Datagram: packets are dropped when a reader falls behind, a redial with
// the same credential replaces the old link at the listener, and closing one
// end leaves the other open. Stream: writes block until the reader takes
// the packet (backpressure), nothing is lost or reordered, and closing
// either end closes both. With both, closing a listener closes the dialers'
// ends too: there is no wire for a restarted listener to pick them up from.
package memory

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	acceptQueue = 64
	linkQueue   = 1024
)

// Name is the transport's name in a registry.
const Name = "memory"

// Semantics is how a network's links behave.
type Semantics int

const (
	Datagram Semantics = iota
	Stream
)

func (s Semantics) String() string {
	if s == Stream {
		return "stream"
	}
	return "datagram"
}

// Addr is an address on a Network.
type Addr string

func (Addr) Network() string  { return "memory" }
func (a Addr) String() string { return string(a) }

// Network is a set of endpoints, and the transport.Transport that reaches
// them.
type Network struct {
	sem       Semantics
	mu        sync.Mutex
	listeners map[string]*Listener
	dials     atomic.Uint64
}

var _ transport.Transport = (*Network)(nil)

// NewNetwork returns an empty network whose links behave as sem says.
func NewNetwork(sem Semantics) *Network {
	return &Network{sem: sem, listeners: make(map[string]*Listener)}
}

func (n *Network) Name() string                   { return Name }
func (n *Network) Dialer() transport.Dialer       { return n }
func (n *Network) Overhead(transport.Shaping) int { return 0 }

var errEmpty = errors.New("memory: empty credential")

func (n *Network) CheckEndpoint(endpoint string, cfg transport.DialConfig) error {
	if endpoint == "" {
		return errors.New("memory: empty endpoint")
	}
	if len(cfg.Credential) == 0 {
		return errEmpty
	}
	return nil
}

func (n *Network) CheckInbound(pl transport.PeerLink) error {
	if len(pl.Verifier) == 0 {
		return errEmpty
	}
	return nil
}

// Listen implements transport.Transport: cfg.Address is any free name.
func (n *Network) Listen(_ context.Context, cfg transport.ListenConfig) (transport.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, taken := n.listeners[cfg.Address]; taken {
		return nil, fmt.Errorf("memory: %s already in use", cfg.Address)
	}
	l := &Listener{
		net: n, addr: Addr(cfg.Address), peers: cfg.Peers, camo: transport.OrDrop(cfg.Camouflage),
		accept: make(chan *end, acceptQueue),
		done:   make(chan struct{}),
		live:   make(map[*end]transport.PeerLink),
	}
	links, changed := cfg.Peers.Snapshot()
	l.links = links
	n.listeners[cfg.Address] = l
	go l.watchPeers(changed)
	return l, nil
}

// Dial implements transport.Dialer. With a credential the listener doesn't
// accept, it returns a link whose packets go to the listener's camouflage.
func (n *Network) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("memory: dial %s: %w", endpoint, err)
	}
	if err := n.CheckEndpoint(endpoint, cfg); err != nil {
		return nil, err
	}
	n.mu.Lock()
	l := n.listeners[endpoint]
	n.mu.Unlock()
	if l == nil {
		return nil, fmt.Errorf("memory: dial %s: connection refused", endpoint)
	}
	local := Addr(fmt.Sprintf("dialer-%d", n.dials.Add(1)))
	return l.connect(ctx, local, cfg.Credential)
}

// Listener is a memory transport listener.
type Listener struct {
	net   *Network
	addr  Addr
	peers transport.Peers
	camo  transport.Camouflage

	accept    chan *end
	done      chan struct{}
	closeOnce sync.Once

	mu    sync.Mutex
	links []transport.PeerLink
	live  map[*end]transport.PeerLink // accepted, open server ends
}

func (l *Listener) connect(ctx context.Context, local Addr, cred []byte) (transport.Link, error) {
	sem := l.net.sem
	client := newEnd(sem, local, l.addr)
	server := newEnd(sem, l.addr, local)
	l.mu.Lock()
	if l.closed() {
		l.mu.Unlock()
		return nil, fmt.Errorf("memory: dial %s: %w", l.addr, transport.ClosedError(nil))
	}
	// Looked up and registered under one lock, so a table change either
	// sees the new end or happened before the lookup.
	pl, ok := lookup(l.links, cred)
	if !ok {
		l.mu.Unlock()
		client.camo = func(p []byte) { l.camo.Datagram(p, local) }
		return client, nil
	}
	server.peer = pl.Peer
	client.other, server.other = server, client
	server.onClose = func() {
		l.mu.Lock()
		delete(l.live, server)
		l.mu.Unlock()
	}
	for e := range l.live {
		if e.closed() { // closed from the dialer's side
			delete(l.live, e)
		}
	}
	l.live[server] = pl
	l.mu.Unlock()

	select {
	case <-l.done:
	case <-ctx.Done():
		_ = server.Close()
		return nil, ctx.Err()
	case l.accept <- server:
		// The older link goes only once the newer one is in.
		l.mu.Lock()
		for e, other := range l.live {
			if e != server && same(other, pl) {
				e.shut(transport.ErrSuperseded)
				delete(l.live, e)
			}
		}
		l.mu.Unlock()
		if !l.closed() {
			return client, nil
		}
	}
	_ = server.Close()
	return nil, fmt.Errorf("memory: dial %s: %w", l.addr, transport.ClosedError(nil))
}

func (l *Listener) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func lookup(links []transport.PeerLink, cred []byte) (transport.PeerLink, bool) {
	for _, pl := range links {
		if len(pl.Verifier) > 0 && subtle.ConstantTimeCompare(pl.Verifier, cred) == 1 {
			return pl, true
		}
	}
	return transport.PeerLink{}, false
}

func same(a, b transport.PeerLink) bool {
	return a.Peer == b.Peer && bytes.Equal(a.Verifier, b.Verifier)
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
		l.mu.Lock()
		l.links = links
		for e, pl := range l.live {
			if cur, ok := lookup(links, pl.Verifier); ok && same(cur, pl) {
				l.live[e] = cur // same credential: new settings apply
				continue
			}
			e.shut(transport.ErrRevoked)
			delete(l.live, e)
		}
		l.mu.Unlock()
	}
}

// Accept implements transport.Listener.
func (l *Listener) Accept(ctx context.Context) (transport.Link, transport.Identity, error) {
	if l.closed() {
		return nil, transport.Identity{}, transport.ClosedError(nil)
	}
	select {
	case <-l.done:
	case <-ctx.Done():
		return nil, transport.Identity{}, ctx.Err()
	case e := <-l.accept:
		if !l.closed() {
			return e, e.peer, nil
		}
	}
	return nil, transport.Identity{}, transport.ClosedError(nil)
}

// Addr implements transport.Listener.
func (l *Listener) Addr() net.Addr { return l.addr }

// Close implements transport.Listener and frees the endpoint.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		close(l.done)
		for e := range l.live {
			e.shut(nil)
			e.other.shut(nil)
		}
		clear(l.live)
		l.mu.Unlock()
		l.net.mu.Lock()
		delete(l.net.listeners, string(l.addr))
		l.net.mu.Unlock()
	})
	return nil
}

// end is one end of a memory link.
type end struct {
	sem           Semantics
	local, remote Addr
	peer          transport.Identity
	other         *end         // nil for a dialer the listener didn't accept
	camo          func([]byte) // where such a dialer's packets go
	onClose       func()

	in        chan []byte
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newEnd(sem Semantics, local, remote Addr) *end {
	return &end{sem: sem, local: local, remote: remote, in: make(chan []byte, linkQueue), done: make(chan struct{})}
}

func (e *end) ReadPacket(p []byte) (int, error) {
	select {
	case <-e.done:
		return 0, e.closeErr
	default:
	}
	select {
	case <-e.done:
		return 0, e.closeErr
	case packet := <-e.in:
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	}
}

func (e *end) WritePacket(p []byte) error {
	if err := transport.CheckPacketSize(p); err != nil {
		return err
	}
	select {
	case <-e.done:
		return e.closeErr
	default:
	}
	c := append([]byte(nil), p...)
	switch {
	case e.other == nil:
		e.camo(c)
	case e.sem == Stream:
		select {
		case e.other.in <- c:
		case <-e.other.done: // closing one end closes both
			e.shut(nil)
			return e.closeErr
		case <-e.done:
			return e.closeErr
		}
	default:
		select {
		case e.other.in <- c:
		default: // reader too slow: drop, as the network would
		}
	}
	return nil
}

func (e *end) Close() error {
	if e.onClose != nil {
		e.onClose()
	}
	e.shut(nil)
	return nil
}

func (e *end) shut(reason error) {
	first := false
	e.closeOnce.Do(func() {
		first = true
		e.closeErr = transport.ClosedError(reason)
		close(e.done)
	})
	if first && e.sem == Stream && e.other != nil {
		e.other.shut(nil) // outside the Once: it comes back here
	}
}

func (e *end) closed() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func (e *end) LocalAddr() net.Addr  { return e.local }
func (e *end) RemoteAddr() net.Addr { return e.remote }
