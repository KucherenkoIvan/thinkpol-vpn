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
// datagram with a Demux, and forwards it untouched to the worker of its
// space; workers reply through the public socket.
type supervisor struct {
	public  net.PacketConn
	demux   *Demux
	camo    transport.Camouflage
	mu      sync.Mutex
	workers map[string]*forwardedConn // by space; "" takes every space
}

func newSupervisor(t *testing.T, address string, peers transport.Peers, camo transport.Camouflage) *supervisor {
	public, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	s := &supervisor{public: public, demux: NewDemux(peers), camo: transport.OrDrop(camo), workers: map[string]*forwardedConn{}}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := public.ReadFrom(buf)
			if err != nil {
				return
			}
			peer, ok := s.demux.Route(buf[:n])
			s.mu.Lock()
			w := s.workers[peer.Space]
			if w == nil {
				w = s.workers[""]
			}
			s.mu.Unlock()
			if !ok || w == nil {
				s.camo.Datagram(buf[:n], from)
				continue
			}
			w.forward(bytes.Clone(buf[:n]), from)
		}
	}()
	return s
}

// worker starts the Listener of one space's worker ("" for all spaces).
func (s *supervisor) worker(space string, peers transport.Peers, camo transport.Camouflage) *Listener {
	fc := &forwardedConn{public: s.public, in: make(chan forwarded, 1024), done: make(chan struct{})}
	s.mu.Lock()
	s.workers[space] = fc
	s.mu.Unlock()
	return NewListener(fc, peers, camo)
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
	received  [][]byte
	mu        sync.Mutex
}

func (fc *forwardedConn) forward(d []byte, from net.Addr) {
	fc.mu.Lock()
	fc.received = append(fc.received, d)
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
	space string
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
// Listener fed by a supervisor's Demux, as on a server node.
func TestConformanceBehindSharedListener(t *testing.T) {
	transporttest.Run(t, transporttest.Harness{
		Listen: func(t *testing.T, endpoint string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, string) {
			if endpoint == "" {
				endpoint = "127.0.0.1:0"
			}
			s := newSupervisor(t, endpoint, peers, camouflage)
			// One worker serves every space here, so the node is down
			// when it is.
			w := s.worker("", peers, camouflage)
			w.pc.(*forwardedConn).onClose = func() { _ = s.public.Close() }
			return w, s.public.LocalAddr().String()
		},
		Dialer:    &Dialer{},
		Interpose: interpose,
	})
}

func TestWorkersGetOnlyTheirOwnLinks(t *testing.T) {
	a, b := transporttest.RandomPeerLink("space-a", "node-1"), transporttest.RandomPeerLink("space-b", "node-1")
	table := transport.NewPeerTable(a, b)
	camo := &transporttest.Recorder{}
	s := newSupervisor(t, "127.0.0.1:0", table, camo)
	defer func() { _ = s.public.Close() }()
	workers := map[string]*Listener{}
	for _, space := range []string{"space-a", "space-b"} {
		workers[space] = s.worker(space, spacePeers{table, space}, nil)
		defer func() { _ = workers[space].Close() }()
	}

	stranger := transporttest.RandomPeerLink("space-a", "node-1")
	for _, pl := range []transport.PeerLink{a, b, stranger} {
		l, err := (&Dialer{}).Dial(context.Background(), s.public.LocalAddr().String(), pl.Config)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		if err := l.WritePacket([]byte("hello from " + pl.Peer.String())); err != nil {
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
	deadline := time.Now().Add(wait)
	for camo.Calls() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if camo.Calls() == 0 {
		t.Fatal("the stranger's datagram never reached the camouflage")
	}
	for space, w := range workers {
		fc := w.pc.(*forwardedConn)
		fc.mu.Lock()
		got := len(fc.received)
		fc.mu.Unlock()
		if got != 1 {
			t.Errorf("worker of %s was forwarded %d datagrams, want 1", space, got)
		}
	}
}

func TestDemuxRoutesAndRejects(t *testing.T) {
	peers := []transport.PeerLink{
		transporttest.RandomPeerLink("space-a", "node-1"),
		transporttest.RandomPeerLink("space-a", "node-2"),
		transporttest.RandomPeerLink("space-b", "node-1"),
	}
	table := transport.NewPeerTable(peers...)
	dm := NewDemux(table)
	datagram := func(pl transport.PeerLink, dir direction, counter uint64) []byte {
		secret := pl.Config.Credential.Secret
		return seal(nil, newAEAD(secret, dir), connIDFor(secret, dir), newSenderID(), counter, []byte("packet"))
	}
	for _, pl := range peers {
		for i := range 2 {
			if id, ok := dm.Route(datagram(pl, toListener, uint64(i))); !ok || id != pl.Peer {
				t.Fatalf("routed %s's datagram to %v (%v)", pl.Peer, id, ok)
			}
		}
	}
	forged := datagram(peers[0], toListener, 0)
	forged[clearSize] ^= 1
	for name, d := range map[string][]byte{
		"forged":          forged,
		"unknown":         datagram(transporttest.RandomPeerLink("space-a", "node-1"), toListener, 0),
		"wrong direction": datagram(peers[0], toDialer, 0),
		"short":           {1, 2, 3},
	} {
		if id, ok := dm.Route(d); ok {
			t.Errorf("%s datagram routed to %s", name, id)
		}
	}
	table.Set(peers[1:])
	if _, ok := dm.Route(datagram(peers[0], toListener, 0)); ok {
		t.Error("routed a revoked credential")
	}
	if id, ok := dm.Route(datagram(peers[1], toListener, 0)); !ok || id != peers[1].Peer {
		t.Error("lost a kept credential on a table change")
	}
}
