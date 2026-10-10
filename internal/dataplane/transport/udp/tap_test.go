package udp

import (
	"bytes"
	"context"
	"errors"
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

// tap is a man in the middle on loopback for one dialer: it forwards
// datagrams between the dialer and a listener, records them as a censor's
// capture would, and can duplicate, inject and change its address toward
// the listener (NAT rebinding).
type tap struct {
	t        *testing.T
	front    net.PacketConn
	listener net.Addr

	mu        sync.Mutex
	client    net.Addr
	back      net.PacketConn
	duplicate bool
	up, down  [][]byte // captured, dialer to listener and back
}

func newTap(t *testing.T, listener net.Addr) *tap {
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
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
			back, dup := tp.back, tp.duplicate
			tp.mu.Unlock()
			_, _ = back.WriteTo(d, listener)
			if dup {
				_, _ = back.WriteTo(d, listener)
			}
		}
	}()
	return tp
}

// rebind moves the tap to a new source port toward the listener.
func (tp *tap) rebind() {
	back, err := net.ListenPacket("udp", "127.0.0.1:0")
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

func (tp *tap) setDuplicate(on bool) {
	tp.mu.Lock()
	tp.duplicate = on
	tp.mu.Unlock()
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
	peer     transport.PeerLink
	camo     *transporttest.Recorder
	listener *Listener
	tap      *tap
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, peer: transporttest.RandomPeerLink("space-a", "node-1"), camo: &transporttest.Recorder{}}
	l, err := Listen("127.0.0.1:0", transport.NewPeerTable(f.peer), f.camo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f.listener = l
	f.tap = newTap(t, l.Addr())
	return f
}

func (f *fixture) dial() transport.Link {
	f.t.Helper()
	l, err := (&Dialer{}).Dial(context.Background(), f.tap.addr(), f.peer.Config)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = l.Close() })
	return l
}

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
	if _, _, err := f.listener.Accept(ctx); err == nil {
		f.t.Fatal("accepted a link that should not exist")
	}
}

// reads collects what a link delivers until it is closed.
func reads(l transport.Link) <-chan []byte {
	ch := make(chan []byte, 1024)
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

func TestProbesGetNoAnswer(t *testing.T) {
	f := newFixture(t)
	secret := f.peer.Config.Credential.Secret
	valid := seal(nil, newAEAD(secret, newSession(), toListener), header{id: connIDFor(secret, toListener), sess: newSession()}, []byte("hi"))
	forged := bytes.Clone(valid)
	forged[len(forged)-1] ^= 1
	wrongDirection := seal(nil, newAEAD(secret, newSession(), toDialer), header{id: connIDFor(secret, toDialer), sess: newSession()}, []byte("hi"))
	probes := map[string][]byte{
		"empty":                     {},
		"one byte":                  {1},
		"WireGuard initiation":      append([]byte{1, 0, 0, 0}, make([]byte, 144)...),
		"zeros":                     make([]byte, 1200),
		"right conn id, bad tag":    forged,
		"right conn id, wrong key":  valid, // sealed under one session, labelled with another
		"other direction's conn id": wrongDirection,
		"oversized":                 make([]byte, maxDatagram+1),
	}
	prober, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prober.Close() }()
	for name, p := range probes {
		before := f.camo.Calls()
		if _, err := prober.WriteTo(p, f.listener.Addr()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		deadline := time.Now().Add(wait)
		for f.camo.Calls() == before && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if f.camo.Calls() == before {
			t.Errorf("%s: never reached the camouflage", name)
		}
	}
	_ = prober.SetReadDeadline(time.Now().Add(quiet))
	if n, _, err := prober.ReadFrom(make([]byte, 65536)); err == nil {
		t.Fatalf("the listener answered a probe with %d bytes", n)
	}
	f.expectNoAccept()
}

func TestReplaysAreDropped(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	f.tap.setDuplicate(true)
	if err := client.WritePacket([]byte("once")); err != nil {
		t.Fatal(err)
	}
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("once"))
	for _, p := range []string{"two", "three"} {
		if err := client.WritePacket([]byte(p)); err != nil {
			t.Fatal(err)
		}
		expectPacket(t, got, []byte(p))
	}
	expectNoPacket(t, got)

	before := f.camo.Calls()
	up, _ := f.tap.captured()
	for _, d := range up {
		f.tap.inject(d)
	}
	expectNoPacket(t, got)
	if f.camo.Calls()-before != int64(len(up)) {
		t.Errorf("%d replays reached the camouflage, want %d", f.camo.Calls()-before, len(up))
	}
}

func TestOldSessionCannotComeBack(t *testing.T) {
	f := newFixture(t)
	first := f.dial()
	if err := first.WritePacket([]byte("first session")); err != nil {
		t.Fatal(err)
	}
	oldServer := f.accept()
	oldUp, _ := f.tap.captured()

	second := f.dial()
	if err := second.WritePacket([]byte("second session")); err != nil {
		t.Fatal(err)
	}
	server := f.accept()
	got := reads(server)
	expectPacket(t, got, []byte("second session"))
	if _, err := oldServer.ReadPacket(make([]byte, transport.MaxPacketSize)); !errors.Is(err, transport.ErrSuperseded) {
		t.Fatalf("old link: %v, want ErrSuperseded", err)
	}

	for _, d := range oldUp {
		f.tap.inject(d)
	}
	if err := first.WritePacket([]byte("first again")); err != nil {
		t.Fatal(err)
	}
	f.expectNoAccept()
	expectNoPacket(t, got)
	// The tap follows whoever spoke last; let the second dialer speak.
	if err := second.WritePacket([]byte("back")); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, got, []byte("back"))
	if err := server.WritePacket([]byte("still the second")); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, reads(second), []byte("still the second"))
}

func TestListenerFollowsARebindingDialer(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	if err := client.WritePacket([]byte("before")); err != nil {
		t.Fatal(err)
	}
	server := f.accept()
	fromClient := reads(server)
	expectPacket(t, fromClient, []byte("before"))
	before := server.RemoteAddr().String()

	f.tap.rebind()
	if err := client.WritePacket([]byte("after")); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, fromClient, []byte("after"))
	if after := server.RemoteAddr().String(); after == before {
		t.Fatalf("remote address still %s after rebinding", after)
	}
	if err := server.WritePacket([]byte("found you")); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, fromServer, []byte("found you"))
}

func TestWireCarriesNoPlaintext(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	marker := []byte("PLAINTEXT-MARKER-0123456789")
	if err := client.WritePacket(marker); err != nil {
		t.Fatal(err)
	}
	server := f.accept()
	if err := server.WritePacket(marker); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, reads(client), marker)
	up, down := f.tap.captured()
	for _, d := range append(up, down...) {
		if bytes.Contains(d, marker[:10]) {
			t.Fatalf("plaintext on the wire: %x", d)
		}
	}
}
