// Package transporttest is the conformance suite every transport passes:
// delivery both ways, packet sizes, bad credentials, many concurrent links,
// superseded and revoked credentials, and closing. An adapter's test calls
// Run with a Harness; adapter-specific behaviour (wire format, probes) is
// tested next to the adapter.
package transporttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// wait bounds anything that must happen; quiet is how long something
	// that must not happen is given to happen anyway.
	wait  = 5 * time.Second
	quiet = 300 * time.Millisecond
)

// Harness is the transport under test.
type Harness struct {
	// Listen starts a listener on a fresh endpoint, accepting peers and
	// sending what fails authentication to camouflage, and returns it with
	// the endpoint dialers use. The suite closes it.
	Listen func(t *testing.T, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, string)
	// Dialer dials the listeners Listen starts.
	Dialer transport.Dialer
}

// Run runs the conformance suite.
func Run(t *testing.T, h Harness) {
	tests := []struct {
		name string
		run  func(*testing.T, Harness)
	}{
		{"Delivery", testDelivery},
		{"PacketSizes", testPacketSizes},
		{"PacketSizeLimits", testPacketSizeLimits},
		{"ShortReadBuffer", testShortReadBuffer},
		{"BadCredential", testBadCredential},
		{"ManyConcurrentLinks", testManyConcurrentLinks},
		{"ConcurrentWrites", testConcurrentWrites},
		{"Superseded", testSuperseded},
		{"Revoked", testRevoked},
		{"CloseLink", testCloseLink},
		{"CloseListener", testCloseListener},
		{"AcceptContext", testAcceptContext},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, h) })
	}
}

// RandomPeerLink returns a peer link with a fresh random secret.
func RandomPeerLink(space, node string) transport.PeerLink {
	secret := make([]byte, transport.MinSecretSize)
	_, _ = rand.Read(secret)
	return transport.PeerLink{
		Peer:   transport.Identity{Space: space, Node: node},
		Config: transport.LinkConfig{Credential: transport.Credential{Secret: secret}},
	}
}

// Recorder is a camouflage that drops everything and counts what it got.
type Recorder struct {
	datagrams atomic.Int64
	streams   atomic.Int64
}

func (r *Recorder) Datagram([]byte, net.Addr) { r.datagrams.Add(1) }

func (r *Recorder) Stream(conn net.Conn, _ []byte) {
	r.streams.Add(1)
	_ = conn.Close()
}

// Calls is how many datagrams and streams the camouflage got.
func (r *Recorder) Calls() int64 { return r.datagrams.Load() + r.streams.Load() }

type env struct {
	t        *testing.T
	h        Harness
	table    *transport.PeerTable
	camo     *Recorder
	listener transport.Listener
	endpoint string
}

func newEnv(t *testing.T, h Harness, peers ...transport.PeerLink) *env {
	e := &env{t: t, h: h, table: transport.NewPeerTable(peers...), camo: &Recorder{}}
	e.listener, e.endpoint = h.Listen(t, e.table, e.camo)
	t.Cleanup(func() { _ = e.listener.Close() })
	return e
}

func (e *env) dial(pl transport.PeerLink) *link {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	l, err := e.h.Dialer.Dial(ctx, e.endpoint, pl.Config)
	if err != nil {
		e.t.Fatalf("dial %s: %v", pl.Peer, err)
	}
	return watch(e.t, l)
}

func (e *env) accept() (*link, transport.Identity) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	l, id, err := e.listener.Accept(ctx)
	if err != nil {
		e.t.Fatalf("accept: %v", err)
	}
	return watch(e.t, l), id
}

func (e *env) expectNoAccept() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), quiet)
	defer cancel()
	if l, id, err := e.listener.Accept(ctx); err == nil {
		_ = l.Close()
		e.t.Fatalf("accepted a link from %s that should not exist", id)
	}
}

// connect dials pl, sends a first packet and accepts the link it opens.
func (e *env) connect(pl transport.PeerLink) (client, server *link) {
	e.t.Helper()
	client = e.dial(pl)
	client.write([]byte("hello"))
	server, id := e.accept()
	if id != pl.Peer {
		e.t.Fatalf("accepted identity %s, want %s", id, pl.Peer)
	}
	server.expect([]byte("hello"))
	return client, server
}

// link reads its packets in the background, so tests can wait on them with
// timeouts.
type link struct {
	t testing.TB
	transport.Link
	packets chan []byte
	err     chan error
}

func watch(t testing.TB, l transport.Link) *link {
	w := &link{t: t, Link: l, packets: make(chan []byte, 1024), err: make(chan error, 1)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		buf := make([]byte, transport.MaxPacketSize)
		for {
			n, err := l.ReadPacket(buf)
			if err != nil {
				w.err <- err
				return
			}
			w.packets <- bytes.Clone(buf[:n])
		}
	}()
	return w
}

func (l *link) write(p []byte) {
	l.t.Helper()
	if err := l.WritePacket(p); err != nil {
		l.t.Fatalf("write %d bytes: %v", len(p), err)
	}
}

// receive waits for the next packet; unlike the methods that fail the
// test, it is safe to call from any goroutine.
func (l *link) receive() ([]byte, error) {
	select {
	case p := <-l.packets:
		return p, nil
	case err := <-l.err:
		return nil, fmt.Errorf("read: %w", err)
	case <-time.After(wait):
		return nil, fmt.Errorf("no packet within %v", wait)
	}
}

func (l *link) receiveEqual(want []byte) error {
	got, err := l.receive()
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("got a %d-byte packet, want %d bytes starting %q", len(got), len(want), want[:min(len(want), 16)])
	}
	return nil
}

func (l *link) next() []byte {
	l.t.Helper()
	p, err := l.receive()
	if err != nil {
		l.t.Fatal(err)
	}
	return p
}

func (l *link) expect(want []byte) {
	l.t.Helper()
	if err := l.receiveEqual(want); err != nil {
		l.t.Fatal(err)
	}
}

func (l *link) expectNothing() {
	l.t.Helper()
	select {
	case p := <-l.packets:
		l.t.Fatalf("got a %d-byte packet that should not arrive", len(p))
	case <-time.After(quiet):
	}
}

// expectClosed waits for reads to fail with net.ErrClosed and, if given,
// reason.
func (l *link) expectClosed(reason error) {
	l.t.Helper()
	select {
	case err := <-l.err:
		if !errors.Is(err, net.ErrClosed) {
			l.t.Fatalf("read error %v, want net.ErrClosed", err)
		}
		if reason != nil && !errors.Is(err, reason) {
			l.t.Fatalf("read error %v, want %v", err, reason)
		}
	case <-time.After(wait):
		l.t.Fatalf("link still open after %v", wait)
	}
}

func randomPacket(size int) []byte {
	p := make([]byte, size)
	_, _ = rand.Read(p)
	return p
}

func testDelivery(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	server.write([]byte("hello back"))
	client.expect([]byte("hello back"))
	for i := range 10 {
		p := []byte(fmt.Sprintf("ping %d", i))
		client.write(p)
		server.expect(p)
		server.write(p)
		client.expect(p)
	}
	for name, a := range map[string]net.Addr{
		"listener": e.listener.Addr(), "client local": client.LocalAddr(), "client remote": client.RemoteAddr(),
		"server local": server.LocalAddr(), "server remote": server.RemoteAddr(),
	} {
		if a == nil || a.String() == "" {
			t.Errorf("%s address is empty", name)
		}
	}
}

func testPacketSizes(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	max := transport.MaxPacketSize
	for _, size := range []int{1, 2, 3, 15, 16, 17, 64, 255, 256, 1280, 1420, 1500, 4096, max - 1, max} {
		up, down := randomPacket(size), randomPacket(size)
		client.write(up)
		server.expect(up)
		server.write(down)
		client.expect(down)
	}
}

func testPacketSizeLimits(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	for name, l := range map[string]*link{"client": client, "server": server} {
		for _, size := range []int{0, transport.MaxPacketSize + 1} {
			if err := l.WritePacket(make([]byte, size)); !errors.Is(err, transport.ErrPacketSize) {
				t.Errorf("%s: writing %d bytes: %v, want ErrPacketSize", name, size, err)
			}
		}
	}
	client.write([]byte("still fine"))
	server.expect([]byte("still fine"))
}

func testShortReadBuffer(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	client := e.dial(pl)
	client.write(randomPacket(100))
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	server, _, err := e.listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	read := func(buf []byte) (int, error) {
		type result struct {
			n   int
			err error
		}
		done := make(chan result, 1)
		go func() { n, err := server.ReadPacket(buf); done <- result{n, err} }()
		select {
		case r := <-done:
			return r.n, r.err
		case <-time.After(wait):
			t.Fatalf("no packet within %v", wait)
			return 0, nil
		}
	}
	if _, err := read(make([]byte, 10)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("reading 100 bytes into 10: %v, want io.ErrShortBuffer", err)
	}
	want := randomPacket(100)
	client.write(want)
	buf := make([]byte, transport.MaxPacketSize)
	n, err := read(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("after a short read: %d bytes, %v", n, err)
	}
}

func testBadCredential(t *testing.T, h Harness) {
	good := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, good)

	short := transport.LinkConfig{Credential: transport.Credential{Secret: make([]byte, transport.MinSecretSize-1)}}
	if l, err := h.Dialer.Dial(context.Background(), e.endpoint, short); err == nil {
		_ = l.Close()
		t.Errorf("dialing with a %d-byte secret succeeded", transport.MinSecretSize-1)
	}

	// Right identity, wrong secret: what a prober who knows everything but
	// the secret would send.
	bad := RandomPeerLink(good.Peer.Space, good.Peer.Node)
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if l, err := h.Dialer.Dial(ctx, e.endpoint, bad.Config); err == nil {
		probe := watch(t, l)
		deadline := time.Now().Add(wait)
		for e.camo.Calls() == 0 && time.Now().Before(deadline) {
			_ = probe.WritePacket([]byte("let me in"))
			time.Sleep(10 * time.Millisecond)
		}
		probe.expectNothing()
	}
	if e.camo.Calls() == 0 {
		t.Errorf("the camouflage never saw the bad credential")
	}
	e.expectNoAccept()

	client, server := e.connect(good)
	server.write([]byte("still serving"))
	client.expect([]byte("still serving"))
}

func testManyConcurrentLinks(t *testing.T, h Harness) {
	const links, rounds = 32, 16
	peers := make([]transport.PeerLink, links)
	for i := range peers {
		peers[i] = RandomPeerLink(fmt.Sprintf("space-%d", i%2), fmt.Sprintf("node-%d", i))
	}
	e := newEnv(t, h, peers...)

	// Server: echo every packet back on the link it came from, after
	// checking that the link's identity matches the hello it starts with.
	go func() {
		for range links {
			l, id, err := e.listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = l.Close() }()
				buf := make([]byte, transport.MaxPacketSize)
				n, err := l.ReadPacket(buf)
				if err != nil {
					return
				}
				var i int
				if _, err := fmt.Sscanf(string(buf[:n]), "hello %d", &i); err != nil || i < 0 || i >= links || peers[i].Peer != id {
					t.Errorf("link accepted as %s said %q", id, buf[:n])
					return
				}
				_ = l.WritePacket(buf[:n])
				for {
					n, err := l.ReadPacket(buf)
					if err != nil {
						return
					}
					_ = l.WritePacket(buf[:n])
				}
			}()
		}
	}()

	var wg sync.WaitGroup
	for i, pl := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pingPong(e, pl, i, rounds); err != nil {
				t.Errorf("link %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
}

// pingPong is one client of testManyConcurrentLinks.
func pingPong(e *env, pl transport.PeerLink, i, rounds int) error {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	l, err := e.h.Dialer.Dial(ctx, e.endpoint, pl.Config)
	if err != nil {
		return err
	}
	client := watch(e.t, l)
	hello := []byte(fmt.Sprintf("hello %d", i))
	if err := client.WritePacket(hello); err != nil {
		return err
	}
	if err := client.receiveEqual(hello); err != nil {
		return err
	}
	for r := range rounds {
		p := randomPacket(1 + (i*rounds+r)*37%1500)
		copy(p, fmt.Sprintf("%d/%d", i, r))
		if err := client.WritePacket(p); err != nil {
			return err
		}
		if err := client.receiveEqual(p); err != nil {
			return fmt.Errorf("round %d: %w", r, err)
		}
	}
	return nil
}

func testConcurrentWrites(t *testing.T, h Harness) {
	const writers, each = 4, 16
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	for _, dir := range []struct {
		name     string
		from, to *link
	}{{"dialer to listener", client, server}, {"listener to dialer", server, client}} {
		var wg sync.WaitGroup
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each {
					if err := dir.from.WritePacket([]byte(fmt.Sprintf("%d-%d", w, i))); err != nil {
						t.Errorf("%s: write: %v", dir.name, err)
					}
				}
			}()
		}
		wg.Wait()
		seen := make(map[string]bool)
		for range writers * each {
			p := string(dir.to.next())
			if seen[p] {
				t.Fatalf("%s: %q delivered twice", dir.name, p)
			}
			seen[p] = true
		}
	}
}

func testSuperseded(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	_, oldServer := e.connect(pl)
	client, server := e.connect(pl)
	oldServer.expectClosed(transport.ErrSuperseded)
	server.write([]byte("new link"))
	client.expect([]byte("new link"))
}

func testRevoked(t *testing.T, h Harness) {
	revoked, kept := RandomPeerLink("space-a", "node-1"), RandomPeerLink("space-a", "node-2")
	e := newEnv(t, h, revoked, kept)
	revokedClient, revokedServer := e.connect(revoked)
	keptClient, keptServer := e.connect(kept)

	e.table.Set([]transport.PeerLink{kept})
	revokedServer.expectClosed(transport.ErrRevoked)
	_ = revokedClient.WritePacket([]byte("still here?"))
	e.expectNoAccept()
	keptClient.write([]byte("kept"))
	keptServer.expect([]byte("kept"))

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if l, err := h.Dialer.Dial(ctx, e.endpoint, revoked.Config); err == nil {
		_ = watch(t, l).WritePacket([]byte("again"))
	}
	e.expectNoAccept()
}

func testCloseLink(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	for name, l := range map[string]*link{"client": client, "server": server} {
		if err := l.Close(); err != nil {
			t.Errorf("%s: close: %v", name, err)
		}
		l.expectClosed(nil)
		if err := l.WritePacket([]byte("x")); !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: write after close: %v, want net.ErrClosed", name, err)
		}
		if _, err := l.ReadPacket(make([]byte, transport.MaxPacketSize)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: read after close: %v, want net.ErrClosed", name, err)
		}
		if err := l.Close(); err != nil {
			t.Errorf("%s: second close: %v", name, err)
		}
	}
}

func testCloseListener(t *testing.T, h Harness) {
	pl := RandomPeerLink("space-a", "node-1")
	e := newEnv(t, h, pl)
	_, server := e.connect(pl)
	accepted := make(chan error, 1)
	go func() {
		_, _, err := e.listener.Accept(context.Background())
		accepted <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := e.listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("pending accept: %v, want net.ErrClosed", err)
		}
	case <-time.After(wait):
		t.Fatalf("pending accept still blocked after close")
	}
	if _, _, err := e.listener.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v, want net.ErrClosed", err)
	}
	server.expectClosed(nil)
}

func testAcceptContext(t *testing.T, h Harness) {
	e := newEnv(t, h, RandomPeerLink("space-a", "node-1"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := e.listener.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("accept with an expiring context: %v, want context.DeadlineExceeded", err)
	}
}
