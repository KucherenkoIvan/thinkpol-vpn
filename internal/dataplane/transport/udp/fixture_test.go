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

const (
	wait  = 5 * time.Second
	quiet = 300 * time.Millisecond
)

// clock is a test clock: real time moved by an offset.
type clock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// tap is a man in the middle on loopback for one dialer at a time: it
// forwards datagrams between the dialer and a listener, records them as a
// censor's capture would, and can hold datagrams back, inject them later,
// and change its address toward the listener (NAT rebinding, or an
// attacker's own address).
type tap struct {
	t        *testing.T
	front    net.PacketConn
	listener net.Addr

	mu       sync.Mutex
	client   net.Addr
	back     net.PacketConn
	holding  bool
	held     [][]byte
	up, down [][]byte // captured, dialer to listener and back
}

func newTap(t *testing.T, listener net.Addr) *tap {
	front, err := net.ListenPacket("udp", loopbackLike(listener))
	if err != nil {
		t.Fatal(err)
	}
	tp := &tap{t: t, front: front, listener: listener}
	t.Cleanup(func() { _ = front.Close() })
	tp.rebind()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := front.ReadFrom(buf)
			if err != nil {
				return
			}
			d := bytes.Clone(buf[:n])
			tp.mu.Lock()
			tp.client = from
			tp.up = append(tp.up, d)
			back, holding := tp.back, tp.holding
			if holding {
				tp.held = append(tp.held, d)
			}
			tp.mu.Unlock()
			if !holding {
				_, _ = back.WriteTo(d, listener)
			}
		}
	}()
	return tp
}

// loopbackLike is a loopback address of the same family as a.
func loopbackLike(a net.Addr) string {
	if ua, ok := a.(*net.UDPAddr); ok && ua.IP.To4() == nil {
		return "[::1]:0"
	}
	return "127.0.0.1:0"
}

// rebind moves the tap to a new source port toward the listener.
func (tp *tap) rebind() {
	back, err := net.ListenPacket("udp", loopbackLike(tp.listener))
	if err != nil {
		tp.t.Fatal(err)
	}
	tp.t.Cleanup(func() { _ = back.Close() })
	tp.mu.Lock()
	tp.back = back
	tp.mu.Unlock()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			d := bytes.Clone(buf[:n])
			tp.mu.Lock()
			tp.down = append(tp.down, d)
			client := tp.client
			tp.mu.Unlock()
			_, _ = tp.front.WriteTo(d, client)
		}
	}()
}

func (tp *tap) addr() string { return tp.front.LocalAddr().String() }

// hold starts or stops holding back what dialers send; held returns it.
func (tp *tap) hold(on bool) {
	tp.mu.Lock()
	tp.holding = on
	tp.mu.Unlock()
}

func (tp *tap) takeHeld() [][]byte {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	held := tp.held
	tp.held = nil
	return held
}

// inject sends d to the listener from the tap's current address.
func (tp *tap) inject(d []byte) {
	tp.mu.Lock()
	back := tp.back
	tp.mu.Unlock()
	if _, err := back.WriteTo(d, tp.listener); err != nil {
		tp.t.Fatal(err)
	}
}

func (tp *tap) captured() (up, down [][]byte) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([][]byte(nil), tp.up...), append([][]byte(nil), tp.down...)
}

type fixture struct {
	t        *testing.T
	clock    *clock
	tr       *Transport
	peer     transporttest.Peer
	table    *transport.PeerTable
	camo     *transporttest.Recorder
	listener *Listener
	tap      *tap
}

func newFixture(t *testing.T) *fixture {
	c := &clock{}
	f := &fixture{
		t: t, clock: c, tr: New(Options{Now: c.now}),
		peer: transporttest.SymmetricPeer(), camo: &transporttest.Recorder{},
	}
	f.table = transport.NewPeerTable(f.peer.PeerLink)
	f.listen("127.0.0.1:0")
	f.tap = newTap(t, f.listener.Addr())
	return f
}

func (f *fixture) listen(address string) {
	f.t.Helper()
	l, err := f.tr.Listen(context.Background(), transport.ListenConfig{Address: address, Peers: f.table, Camouflage: f.camo})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = l.Close() })
	f.listener = l.(*Listener)
}

// restart closes the listener and starts another on the same address.
func (f *fixture) restart() {
	f.t.Helper()
	addr := f.listener.Addr().String()
	_ = f.listener.Close()
	f.listen(addr)
}

func (f *fixture) dialWith(tr *Transport) transport.Link {
	f.t.Helper()
	l, err := tr.Dial(context.Background(), f.tap.addr(), transport.DialConfig{Credential: f.peer.Credential})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = l.Close() })
	return l
}

func (f *fixture) dial() transport.Link { return f.dialWith(f.tr) }

func (f *fixture) accept() transport.Link {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	l, _, err := f.listener.Accept(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = l.Close() })
	return l
}

func (f *fixture) expectNoAccept() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), quiet)
	defer cancel()
	if _, id, err := f.listener.Accept(ctx); err == nil {
		f.t.Fatalf("accepted a link from %s that should not exist", id)
	} else if err != context.DeadlineExceeded {
		f.t.Fatalf("the listener died: %v", err)
	}
}

// reads collects what a link delivers until it is closed.
func reads(l transport.Link) <-chan []byte {
	ch := make(chan []byte, 4096)
	go func() {
		defer close(ch)
		buf := make([]byte, transport.MaxPacketSize)
		for {
			n, err := l.ReadPacket(buf)
			if err != nil {
				return
			}
			ch <- bytes.Clone(buf[:n])
		}
	}()
	return ch
}

func expectPacket(t *testing.T, ch <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-ch:
		if !bytes.Equal(got, want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	case <-time.After(wait):
		t.Fatalf("%q never arrived", want)
	}
}

func expectNoPacket(t *testing.T, ch <-chan []byte) {
	t.Helper()
	select {
	case got, ok := <-ch:
		if ok {
			t.Fatalf("got %q, which should not arrive", got)
		}
	case <-time.After(quiet):
	}
}

// waitFor polls cond until it holds or wait runs out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: never happened", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func write(t *testing.T, l transport.Link, p string) {
	t.Helper()
	if err := l.WritePacket([]byte(p)); err != nil {
		t.Fatal(err)
	}
}
