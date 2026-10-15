package udp

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// supervisor is the shared listener of DESIGN.md "Server agent", reduced to
// what the transport has to support: it owns the public socket, routes each
// datagram with the transport's Router, and forwards it untouched to the
// worker of its space; workers reply through the public socket.
type supervisor struct {
	public  net.PacketConn
	router  transport.Router
	camo    transport.Camouflage
	mu      sync.Mutex
	workers map[transport.SpaceID]*forwardedConn
	any     *forwardedConn // a single worker for every space
}

func newSupervisor(t *testing.T, tr *Transport, address string, peers transport.Peers, camo transport.Camouflage) *supervisor {
	public, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	s := &supervisor{public: public, router: tr.Router(peers), camo: transport.OrDrop(camo), workers: map[transport.SpaceID]*forwardedConn{}}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := public.ReadFrom(buf)
			if err != nil {
				return
			}
			peer, v := s.router.RouteDatagram(buf[:n])
			s.mu.Lock()
			w := s.workers[peer.Space]
			if w == nil {
				w = s.any
			}
			s.mu.Unlock()
			if v != transport.Routed || w == nil {
				s.camo.Datagram(buf[:n], from)
				continue
			}
			w.forward(bytes.Clone(buf[:n]), from)
		}
	}()
	return s
}

// worker starts the Listener of one space's worker, or of every space.
func (s *supervisor) worker(tr *Transport, space *transport.SpaceID, peers transport.Peers, camo transport.Camouflage) *Listener {
	fc := &forwardedConn{public: s.public, in: make(chan forwarded, 1024), done: make(chan struct{})}
	s.mu.Lock()
	if space == nil {
		s.any = fc
	} else {
		s.workers[*space] = fc
	}
	s.mu.Unlock()
	return tr.ListenOn(fc, transport.ListenConfig{Peers: peers, Camouflage: camo})
}

type forwarded struct {
	d    []byte
	from net.Addr
}

// forwardedConn is a worker's view of the public socket: it reads what the
// supervisor forwards and writes replies out through the public socket. In
// the real agent the two sides talk over a Unix socket.
type forwardedConn struct {
	public    net.PacketConn
	in        chan forwarded
	done      chan struct{}
	closeOnce sync.Once
	onClose   func()
	mu        sync.Mutex
	received  int
}

func (fc *forwardedConn) forward(d []byte, from net.Addr) {
	fc.mu.Lock()
	fc.received++
	fc.mu.Unlock()
	select {
	case fc.in <- forwarded{d, from}:
	case <-fc.done:
	}
}

func (fc *forwardedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case f := <-fc.in:
		return copy(p, f.d), f.from, nil
	case <-fc.done:
		return 0, nil, net.ErrClosed
	}
}

func (fc *forwardedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return fc.public.WriteTo(p, addr)
}

func (fc *forwardedConn) Close() error {
	fc.closeOnce.Do(func() {
		close(fc.done)
		if fc.onClose != nil {
			fc.onClose()
		}
	})
	return nil
}

func (fc *forwardedConn) LocalAddr() net.Addr              { return fc.public.LocalAddr() }
func (fc *forwardedConn) SetDeadline(time.Time) error      { return nil }
func (fc *forwardedConn) SetReadDeadline(time.Time) error  { return nil }
func (fc *forwardedConn) SetWriteDeadline(time.Time) error { return nil }

// spacePeers is one space's slice of a shared peer table.
type spacePeers struct {
	all   transport.Peers
	space transport.SpaceID
}

func (sp spacePeers) Snapshot() ([]transport.PeerLink, <-chan struct{}) {
	links, changed := sp.all.Snapshot()
	var mine []transport.PeerLink
	for _, pl := range links {
		if pl.Peer.Space == sp.space {
			mine = append(mine, pl)
		}
	}
	return mine, changed
}

// TestConformanceBehindSharedListener runs the suite with a worker's
// Listener fed by a supervisor's Router, as on a server node.
func TestConformanceBehindSharedListener(t *testing.T) {
	tr := New(Options{})
	transporttest.Run(t, transporttest.Harness{
		Listen: func(t *testing.T, address string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
			if address == "" {
				address = "127.0.0.1:0"
			}
			s := newSupervisor(t, tr, address, peers, camouflage)
			// One worker serves every space here, so the node is down
			// when it is.
			w := s.worker(tr, nil, peers, camouflage)
			w.pc.(*forwardedConn).onClose = func() { _ = s.public.Close() }
			return w, transporttest.Endpoint{Address: s.public.LocalAddr().String()}
		},
		Dialer:    tr.Dialer(),
		Interpose: interpose,
	})
}

func TestWorkersGetOnlyTheirOwnLinks(t *testing.T) {
	tr := New(Options{})
	a, b := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	table := transport.NewPeerTable(a.PeerLink, b.PeerLink)
	camo := &transporttest.Recorder{}
	s := newSupervisor(t, tr, "127.0.0.1:0", table, camo)
	defer func() { _ = s.public.Close() }()
	workers := map[transport.SpaceID]*Listener{}
	for _, space := range []transport.SpaceID{a.Peer.Space, b.Peer.Space} {
		workers[space] = s.worker(tr, &space, spacePeers{table, space}, nil)
		defer func() { _ = workers[space].Close() }()
	}

	stranger := transporttest.SymmetricPeer()
	stranger.Peer = a.Peer
	for _, p := range []transporttest.Peer{a, b, stranger} {
		l, err := tr.Dial(context.Background(), s.public.LocalAddr().String(), transport.DialConfig{Credential: p.Credential})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		if err := l.WritePacket([]byte("hello from " + p.Peer.String())); err != nil {
			t.Fatal(err)
		}
	}
	for space, w := range workers {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		l, id, err := w.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", space, err)
		}
		if id.Space != space {
			t.Fatalf("worker of %s accepted a link of %s", space, id)
		}
		buf := make([]byte, transport.MaxPacketSize)
		n, err := l.ReadPacket(buf)
		if err != nil || string(buf[:n]) != "hello from "+id.String() {
			t.Fatalf("%s: read %q, %v", space, buf[:n], err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), quiet)
		if _, id, err := w.Accept(ctx); err == nil {
			t.Fatalf("worker of %s accepted a second link, of %s", space, id)
		}
		cancel()
	}
	waitFor(t, "the stranger reaching the camouflage", func() bool { return camo.Calls() > 0 })
	for space, w := range workers {
		fc := w.pc.(*forwardedConn)
		fc.mu.Lock()
		got := fc.received
		fc.mu.Unlock()
		if got != 1 {
			t.Errorf("worker of %s was forwarded %d datagrams, want 1", space, got)
		}
	}
}

func TestRouterRoutesAndRejects(t *testing.T) {
	c := &clock{}
	tr := New(Options{Now: c.now})
	peers := []transporttest.Peer{transporttest.SymmetricPeer(), transporttest.SymmetricPeer(), transporttest.SymmetricPeer()}
	twin := peers[2]
	twin.Peer = transporttest.RandomIdentity()
	table := transport.NewPeerTable(peers[0].PeerLink, peers[1].PeerLink, peers[2].PeerLink, twin.PeerLink)
	r := tr.Router(table).(*Router)
	datagram := func(p transporttest.Peer, dir direction, at time.Time) []byte {
		return seal(nil, newAEAD(p.Credential, dir), connIDFor(p.Credential, dir, epochOf(at)), newSenderID(at), at, 0, []byte("packet"), transport.Padding{})
	}
	now := c.now()
	for _, p := range peers[:2] {
		d := datagram(p, toListener, now)
		if id, v := r.RouteDatagram(d); v != transport.Routed || id != p.Peer {
			t.Fatalf("routed %s's datagram to %v (%v)", p.Peer, id, v)
		}
		if id, v := r.RouteDatagram(d); v != transport.Replayed || id != p.Peer {
			t.Fatalf("%s's datagram again: %v (%v), want a replay", p.Peer, id, v)
		}
	}
	forged := datagram(peers[0], toListener, now)
	forged[clearSize] ^= 1
	for name, d := range map[string][]byte{
		"forged":           forged,
		"unknown":          datagram(transporttest.SymmetricPeer(), toListener, now),
		"wrong direction":  datagram(peers[0], toDialer, now),
		"duplicate secret": datagram(peers[2], toListener, now),
		"short":            {1, 2, 3},
	} {
		if id, v := r.RouteDatagram(d); v != transport.Unknown {
			t.Errorf("%s datagram: %v for %s", name, v, id)
		}
	}
	// Unknown sender and old sealed time: clock skew, not replay.
	if id, v := r.RouteDatagram(datagram(peers[0], toListener, now.Add(-6*time.Minute))); v != transport.StaleClock || id != peers[0].Peer {
		t.Errorf("a datagram sent 6 minutes ago: %v for %s", v, id)
	}
	if got := r.Counters().StaleTimestamp; got != 1 {
		t.Errorf("counted %d stale timestamps, want 1", got)
	}
	if got := len(r.Rejected()); got != 2 {
		t.Errorf("reported %d unusable peer links, want the 2 sharing a secret", got)
	}
	if _, _, ok := r.RouteStream(nil); ok {
		t.Error("udp routed a stream")
	}
	table.Set([]transport.PeerLink{peers[1].PeerLink})
	if _, v := r.RouteDatagram(datagram(peers[0], toListener, now)); v != transport.Unknown {
		t.Error("routed a revoked credential")
	}
	if id, v := r.RouteDatagram(datagram(peers[1], toListener, now)); v != transport.Routed || id != peers[1].Peer {
		t.Error("lost a kept credential on a table change")
	}
	// Its history survives the table change, and a secret taken out and
	// put back: replays stay replays.
	replay := datagram(peers[0], toListener, now)
	table.Set([]transport.PeerLink{peers[0].PeerLink, peers[1].PeerLink})
	if _, v := r.RouteDatagram(replay); v != transport.Routed {
		t.Fatalf("a fresh datagram of a returning secret: %v", v)
	}
	table.Set([]transport.PeerLink{peers[1].PeerLink})
	r.Rejected() // picks up the change
	table.Set([]transport.PeerLink{peers[0].PeerLink, peers[1].PeerLink})
	if _, v := r.RouteDatagram(replay); v != transport.Replayed {
		t.Fatalf("a replay after the secret left and came back: %v", v)
	}
}

func TestRouterStaleSender(t *testing.T) {
	c := &clock{}
	tr := New(Options{Now: c.now})
	peers := []transporttest.Peer{transporttest.SymmetricPeer()}
	table := transport.NewPeerTable(peers[0].PeerLink)
	r := tr.Router(table).(*Router)
	now := c.now()
	newer := senderIDFor(now.UnixNano())
	older := senderIDFor(now.UnixNano() - int64(time.Second))
	datagram := func(sender senderID, counter uint64, at time.Time) []byte {
		return seal(nil, newAEAD(peers[0].Credential, toListener), connIDFor(peers[0].Credential, toListener, epochOf(at)), sender, at, counter, []byte("packet"), transport.Padding{})
	}
	if _, v := r.RouteDatagram(datagram(newer, 0, now)); v != transport.Routed {
		t.Fatalf("newer sender: %v", v)
	}
	if id, v := r.RouteDatagram(datagram(older, 0, now)); v != transport.StaleSender || id != peers[0].Peer {
		t.Fatalf("older sender: %v for %s", v, id)
	}
}
