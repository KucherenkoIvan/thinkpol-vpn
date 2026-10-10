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
// loopbackLike is a loopback address of the same family as a.
func loopbackLike(a net.Addr) string {
	if ua, ok := a.(*net.UDPAddr); ok && ua.IP.To4() == nil {
		return "[::1]:0"
	}
	return "127.0.0.1:0"
}

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
	inID := connIDFor(secret, toListener)
	forged := seal(nil, newAEAD(secret, toListener), inID, newSenderID(), 0, []byte("hi"))
	forged[len(forged)-1] ^= 1
	probes := map[string][]byte{
		"empty":                     {},
		"one byte":                  {1},
		"WireGuard initiation":      append([]byte{1, 0, 0, 0}, make([]byte, 144)...),
		"zeros":                     make([]byte, 1200),
		"right conn id, bad tag":    forged,
		"right conn id, wrong key":  seal(nil, newAEAD(randomSecret(t), toListener), inID, newSenderID(), 0, []byte("hi")),
		"other direction's conn id": seal(nil, newAEAD(secret, toDialer), connIDFor(secret, toDialer), newSenderID(), 0, []byte("hi")),
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

// TestReplayFromElsewhereDoesNotMoveTheLink replays a captured datagram from
// another address: it is not the newest of its sender, so the link stays.
func TestReplayFromElsewhereDoesNotMoveTheLink(t *testing.T) {
	f := newFixture(t)
	client := f.dial()
	fromServer := reads(client)
	for _, p := range []string{"one", "two"} {
		if err := client.WritePacket([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	server := f.accept()
	fromClient := reads(server)
	expectPacket(t, fromClient, []byte("one"))
	expectPacket(t, fromClient, []byte("two"))
	before := server.RemoteAddr().String()
	up, _ := f.tap.captured()
	f.tap.rebind()
	f.tap.inject(up[0])
	expectNoPacket(t, fromClient)
	if after := server.RemoteAddr().String(); after != before {
		t.Fatalf("a replay moved the link from %s to %s", before, after)
	}
	if err := server.WritePacket([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, fromServer, []byte("still here"))
}

// TestNoncesNeverRepeat checks the wire across everything that resets a
// sender: a redial, a listener restart, a server-side close.
func TestNoncesNeverRepeat(t *testing.T) {
	f := newFixture(t)
	addr := f.listener.Addr().String()
	exchange := func(client transport.Link) {
		t.Helper()
		if err := client.WritePacket([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		server := f.accept()
		expectPacket(t, reads(server), []byte("ping"))
		for range 10 {
			if err := server.WritePacket([]byte("pong")); err != nil {
				t.Fatal(err)
			}
		}
		_ = server.Close()
	}
	exchange(f.dial())
	exchange(f.dial())
	_ = f.listener.Close()
	l, err := Listen(addr, transport.NewPeerTable(f.peer), f.camo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f.listener = l
	exchange(f.dial())
	time.Sleep(quiet)
	up, down := f.tap.captured()
	seen := map[string]bool{}
	for _, d := range append(up, down...) {
		n := string(d[connIDSize:clearSize])
		if seen[n] {
			t.Fatalf("nonce %x used twice", n)
		}
		seen[n] = true
	}
	if len(seen) < 30 {
		t.Fatalf("only %d datagrams captured", len(seen))
	}
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
