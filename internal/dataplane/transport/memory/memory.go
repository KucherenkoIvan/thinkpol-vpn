// Package memory is an in-process transport: links between listeners and
// dialers of one Network, with no sockets. It behaves like a datagram
// transport (packets may be dropped when a reader falls behind, nothing
// answers bad credentials) and passes the conformance suite, so the layers
// above can be tested on it.
package memory

import (
	"context"
	"crypto/subtle"
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

// Addr is an address on a Network.
type Addr string

func (Addr) Network() string  { return "memory" }
func (a Addr) String() string { return string(a) }

// Network is a set of endpoints. Its zero value is not usable; see
// NewNetwork.
type Network struct {
	mu        sync.Mutex
	listeners map[string]*Listener
	dials     atomic.Uint64
}

// NewNetwork returns an empty network.
func NewNetwork() *Network {
	return &Network{listeners: make(map[string]*Listener)}
}

// Listen listens on endpoint, which must be free. A nil camouflage drops
// everything unauthenticated.
func (n *Network) Listen(endpoint string, peers transport.Peers, camouflage transport.Camouflage) (*Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, taken := n.listeners[endpoint]; taken {
		return nil, fmt.Errorf("memory: %s already in use", endpoint)
	}
	l := &Listener{
		net: n, addr: Addr(endpoint), peers: peers, camo: transport.OrDrop(camouflage),
		accept: make(chan *end, acceptQueue),
		done:   make(chan struct{}),
		live:   make(map[*end]transport.PeerLink),
	}
	links, changed := peers.Snapshot()
	l.links = links
	n.listeners[endpoint] = l
	go l.watchPeers(changed)
	return l, nil
}

// Dial implements transport.Dialer. With a credential the listener doesn't
// accept, it returns a link whose packets go to the listener's camouflage.
func (n *Network) Dial(ctx context.Context, endpoint string, cfg transport.LinkConfig) (transport.Link, error) {
	if err := cfg.Credential.Validate(); err != nil {
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

func (l *Listener) connect(ctx context.Context, local Addr, cred transport.Credential) (transport.Link, error) {
	client := newEnd(local, l.addr)
	l.mu.Lock()
	pl, ok := lookup(l.links, cred)
	l.mu.Unlock()
	if !ok {
		client.toPeer = func(p []byte) { l.camo.Datagram(p, local) }
		return client, nil
	}
	server := newEnd(l.addr, local)
	server.peer = pl.Peer
	client.toPeer = server.deliver
	server.toPeer = client.deliver
	server.onClose = func() {
		l.mu.Lock()
		delete(l.live, server)
		l.mu.Unlock()
	}
	l.mu.Lock()
	for e, other := range l.live {
		if same(other, pl) {
			e.shut(transport.ErrSuperseded)
			delete(l.live, e)
		}
	}
	l.live[server] = pl
	l.mu.Unlock()
	select {
	case <-l.done:
		_ = server.Close()
		return nil, fmt.Errorf("memory: dial %s: %w", l.addr, transport.ClosedError(nil))
	case <-ctx.Done():
		_ = server.Close()
		return nil, ctx.Err()
	case l.accept <- server:
		return client, nil
	}
}

func lookup(links []transport.PeerLink, cred transport.Credential) (transport.PeerLink, bool) {
	for _, pl := range links {
		if pl.Config.Credential.Validate() == nil &&
			subtle.ConstantTimeCompare(pl.Config.Credential.Secret, cred.Secret) == 1 {
			return pl, true
		}
	}
	return transport.PeerLink{}, false
}

func same(a, b transport.PeerLink) bool {
	return a.Peer == b.Peer && subtle.ConstantTimeCompare(a.Config.Credential.Secret, b.Config.Credential.Secret) == 1
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
			if cur, ok := lookup(links, pl.Config.Credential); !ok || !same(cur, pl) {
				e.shut(transport.ErrRevoked)
				delete(l.live, e)
			}
		}
		l.mu.Unlock()
	}
}

// Accept implements transport.Listener.
func (l *Listener) Accept(ctx context.Context) (transport.Link, transport.Identity, error) {
	select {
	case <-l.done:
		return nil, transport.Identity{}, transport.ClosedError(nil)
	default:
	}
	select {
	case <-l.done:
		return nil, transport.Identity{}, transport.ClosedError(nil)
	case <-ctx.Done():
		return nil, transport.Identity{}, ctx.Err()
	case e := <-l.accept:
		return e, e.peer, nil
	}
}

// Addr implements transport.Listener.
func (l *Listener) Addr() net.Addr { return l.addr }

// Close implements transport.Listener and frees the endpoint.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.net.mu.Lock()
		delete(l.net.listeners, string(l.addr))
		l.net.mu.Unlock()
		l.mu.Lock()
		for e := range l.live {
			e.shut(nil)
		}
		clear(l.live)
		l.mu.Unlock()
		for {
			select {
			case e := <-l.accept:
				e.shut(nil)
			default:
				return
			}
		}
	})
	return nil
}

// end is one end of a memory link.
type end struct {
	local, remote Addr
	peer          transport.Identity
	toPeer        func([]byte)
	onClose       func()

	in        chan []byte
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newEnd(local, remote Addr) *end {
	return &end{local: local, remote: remote, in: make(chan []byte, linkQueue), done: make(chan struct{})}
}

func (e *end) deliver(p []byte) {
	select {
	case <-e.done:
	case e.in <- p:
	default: // reader too slow: drop, as the network would
	}
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
	e.toPeer(append([]byte(nil), p...))
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
	e.closeOnce.Do(func() {
		e.closeErr = transport.ClosedError(reason)
		close(e.done)
	})
}

func (e *end) LocalAddr() net.Addr  { return e.local }
func (e *end) RemoteAddr() net.Addr { return e.remote }
