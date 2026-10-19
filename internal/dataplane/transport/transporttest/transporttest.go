// Package transporttest is the conformance suite every transport passes:
// delivery both ways, packet sizes, bad credentials, dial deadlines, many
// concurrent links, concurrent writes, redials, replays (with a man in the
// middle the harness provides), table changes and revocations (also racing
// a dial), closing links and listeners (also racing traffic, without leaking
// goroutines), writes unblocked by Close, listener restarts, control
// packets, and shaping: links shaped at one end only, shaping changed on a
// live link, and shaping the adapter can't honour refused everywhere. An
// adapter's test calls Run with a Harness, once without shaping and once
// per kind of shaping it implements; adapter-specific behaviour (wire
// format, what shaping looks like on it, probes, clocks) is tested next to
// the adapter. Buckets is the padding constructor tests across the data
// plane and the map share.
package transporttest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
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
	// Listen starts a listener accepting peers and sending what fails
	// authentication to camouflage, and returns it with the endpoint dialers
	// use. address is "" for a fresh endpoint, or the Address of one whose
	// listener the suite closed (a restart). The suite closes the listener.
	Listen func(t *testing.T, address string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, Endpoint)
	// Dialer dials the listeners Listen starts.
	Dialer transport.Dialer
	// Credentials, if set, makes a dialer's credential and the listener's
	// verifier for it; otherwise both are the same random 32-byte secret.
	Credentials func() (credential, verifier []byte)
	// Interpose, if set, puts a man in the middle in front of address. It
	// returns the address to dial instead, and replay, which sends the
	// listener again everything dialers sent through it so far. Transports
	// with a wire set it; without it the Replay test is skipped.
	Interpose func(t *testing.T, address string) (front string, replay func())
	// Shaping is applied at both ends of every link the suite opens.
	Shaping transport.Shaping
	// Refused are shapings the adapter can't honour: dials and peer links
	// asking for them must be refused. Invalid shapings are always tried.
	Refused []transport.Shaping
	// Transport, if set, is the adapter: the suite checks its
	// CheckEndpoint, CheckInbound and Overhead too.
	Transport transport.Transport
}

// Endpoint is where and how dialers reach a listener the harness started.
type Endpoint struct {
	Address  string
	Settings []byte // the transport's dial settings
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
		{"DialDeadline", testDialDeadline},
		{"ManyConcurrentLinks", testManyConcurrentLinks},
		{"ConcurrentWrites", testConcurrentWrites},
		{"Redial", testRedial},
		{"Replay", testReplay},
		{"TableChangeKeepsLinks", testTableChangeKeepsLinks},
		{"Revoked", testRevoked},
		{"RevocationRacingDial", testRevocationRacingDial},
		{"CloseLink", testCloseLink},
		{"WriteUnblocksOnClose", testWriteUnblocksOnClose},
		{"CloseListener", testCloseListener},
		{"ListenerRestart", testListenerRestart},
		{"CloseRacesLeakNothing", testCloseRacesLeakNothing},
		{"AcceptContext", testAcceptContext},
		{"ControlPackets", testControlPackets},
		{"ShapingOneSided", testShapingOneSided},
		{"ShapingChange", testShapingChange},
		{"ShapingRefused", testShapingRefused},
		{"Overhead", testOverhead},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, h) })
	}
}

// Peer is a dialer as the suite sees it: the listener's entry for it and
// the credential it dials with.
type Peer struct {
	transport.PeerLink
	Credential []byte
}

// RandomIdentity returns random space and node ids.
func RandomIdentity() transport.Identity {
	var id transport.Identity
	_, _ = rand.Read(id.Space[:])
	_, _ = rand.Read(id.Node[:])
	return id
}

// SymmetricPeer returns a peer with a random identity whose credential and
// verifier are the same random 32-byte secret.
func SymmetricPeer() Peer {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return Peer{PeerLink: transport.PeerLink{Peer: RandomIdentity(), Verifier: secret}, Credential: secret}
}

func (h Harness) peer() Peer {
	p := SymmetricPeer()
	if h.Credentials != nil {
		cred, verifier := h.Credentials()
		p = Peer{PeerLink: transport.PeerLink{Peer: RandomIdentity(), Verifier: verifier}, Credential: cred}
	}
	p.Shaping = h.Shaping
	return p
}

func links(peers ...Peer) []transport.PeerLink {
	out := make([]transport.PeerLink, len(peers))
	for i, p := range peers {
		out[i] = p.PeerLink
	}
	return out
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
	endpoint Endpoint // where the listener is
	dialTo   string   // where dialers go: the endpoint, or a man in the middle
}

func newEnv(t *testing.T, h Harness, peers ...Peer) *env {
	e := &env{t: t, h: h, table: transport.NewPeerTable(links(peers...)...), camo: &Recorder{}}
	e.listen("")
	e.dialTo = e.endpoint.Address
	return e
}

func (e *env) dialConfig(p Peer) transport.DialConfig {
	return transport.DialConfig{Credential: p.Credential, Settings: e.endpoint.Settings, Shaping: e.h.Shaping}
}

func (e *env) listen(address string) {
	e.listener, e.endpoint = e.h.Listen(e.t, address, e.table, e.camo)
	l := e.listener
	e.t.Cleanup(func() { _ = l.Close() })
}

// restart closes the listener and starts a new one at the same endpoint.
func (e *env) restart() {
	e.t.Helper()
	if err := e.listener.Close(); err != nil {
		e.t.Fatalf("close: %v", err)
	}
	e.listen(e.endpoint.Address)
}

func (e *env) dial(pl Peer) *link {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	l, err := e.h.Dialer.Dial(ctx, e.dialTo, e.dialConfig(pl))
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
	l, id, err := e.listener.Accept(ctx)
	switch {
	case err == nil:
		_ = l.Close()
		e.t.Fatalf("accepted a link from %s that should not exist", id)
	case !errors.Is(err, context.DeadlineExceeded):
		e.t.Fatalf("the listener died: %v", err)
	}
}

// connect dials pl, sends a first packet and accepts the link it opens.
func (e *env) connect(pl Peer) (client, server *link) {
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

// connectAdmitted is connect for a peer link a table change has just
// admitted. Listeners may take the change in the background, and until
// they have, a dial is camouflaged (and some transports decide that when
// they dial), so it dials again until a link is accepted, waiting longer
// each time.
func (e *env) connectAdmitted(pl Peer) (client, server *link) {
	e.t.Helper()
	deadline := time.Now().Add(wait)
	for patience := quiet; ; patience *= 2 {
		client = e.dial(pl)
		client.write([]byte("hello"))
		ctx, cancel := context.WithTimeout(context.Background(), min(patience, time.Until(deadline)))
		l, id, err := e.listener.Accept(ctx)
		cancel()
		if err == nil {
			if id != pl.Peer {
				e.t.Fatalf("accepted identity %s, want %s", id, pl.Peer)
			}
			server = watch(e.t, l)
			server.expect([]byte("hello"))
			return client, server
		}
		if !errors.Is(err, context.DeadlineExceeded) || time.Now().After(deadline) {
			e.t.Fatalf("accept: %v", err)
		}
		_ = client.Close()
	}
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
	pl := h.peer()
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
	pl := h.peer()
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
	pl := h.peer()
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
	pl := h.peer()
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
	good := h.peer()
	e := newEnv(t, h, good)

	// Right identity, wrong secret: what a prober who knows everything but
	// the secret would send.
	bad := h.peer()
	bad.Peer = good.Peer
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if l, err := h.Dialer.Dial(ctx, e.dialTo, e.dialConfig(bad)); err == nil {
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

// testManyConcurrentLinks ping-pongs on many links at once. A datagram
// transport may lose a packet as any network may (a socket buffer
// overflowing while a loaded machine holds its reader up), so a client
// whose echo is late sends the round again; a transport that loses packets
// itself still fails (see maxLost).
func testManyConcurrentLinks(t *testing.T, h Harness) {
	const links, rounds = 32, 16
	peers := make([]Peer, links)
	for i := range peers {
		peers[i] = h.peer()
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
	var sent, lost atomic.Int64
	for i, pl := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, l, err := pingPong(e, pl, i, rounds)
			sent.Add(int64(s))
			lost.Add(int64(l))
			if err != nil {
				t.Errorf("link %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if n, of := lost.Load(), sent.Load(); n > maxLost {
		t.Errorf("%d of %d packets never came back", n, of)
	} else if n > 0 || of > links*(rounds+1) {
		t.Logf("%d packets sent for %d rounds, %d never came back", of, links*(rounds+1), n)
	}
}

// resendAfter is how long a ping-pong client waits for an echo before it
// sends the round again.
const resendAfter = time.Second

// maxLost is how many of testManyConcurrentLinks' 544 or more round trips
// may never come back: the odd datagram a loaded machine's socket buffer
// drops. An absolute bound, not a share, so a transport losing even 1% per
// direction (about 11 round trips) fails.
const maxLost = 3

// pingPong is one client of testManyConcurrentLinks. A round's resend is a
// new packet of the same size, so each echo says which one came back. It
// returns how many packets it sent and how many of them never came back.
func pingPong(e *env, pl Peer, i, rounds int) (sent, lost int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	l, err := e.h.Dialer.Dial(ctx, e.dialTo, e.dialConfig(pl))
	if err != nil {
		return 0, 0, err
	}
	client := watch(e.t, l)
	outstanding := map[string]int{} // sent, not yet echoed
	exchange := func(packet func() []byte) error {
		deadline := time.After(wait)
		round := map[string]bool{}
		for {
			p := packet()
			if err := client.WritePacket(p); err != nil {
				return err
			}
			sent++
			outstanding[string(p)]++
			round[string(p)] = true
			resend := time.After(resendAfter)
		echoes:
			for {
				select {
				case got := <-client.packets:
					if outstanding[string(got)] == 0 {
						return fmt.Errorf("got a %d-byte packet nobody sent", len(got))
					}
					outstanding[string(got)]--
					if round[string(got)] {
						return nil
					}
				case err := <-client.err:
					return fmt.Errorf("read: %w", err)
				case <-resend:
					break echoes
				case <-deadline:
					return fmt.Errorf("no echo within %v", wait)
				}
			}
		}
	}
	defer func() {
		// Late echoes of resent rounds still count as delivered.
		drain := time.After(quiet)
		for err == nil {
			n := 0
			for _, c := range outstanding {
				n += c
			}
			if n == 0 {
				break
			}
			select {
			case got := <-client.packets:
				if outstanding[string(got)] == 0 {
					err = fmt.Errorf("got a %d-byte packet nobody sent", len(got))
				}
				outstanding[string(got)]--
			case <-drain:
				lost = n
				return
			}
		}
	}()
	hello := []byte(fmt.Sprintf("hello %d", i))
	if err := exchange(func() []byte { return hello }); err != nil {
		return sent, 0, err
	}
	for r := range rounds {
		size := 1 + (i*rounds+r)*37%1500
		err := exchange(func() []byte {
			p := randomPacket(size)
			copy(p, fmt.Sprintf("%d/%d", i, r))
			return p
		})
		if err != nil {
			return sent, 0, fmt.Errorf("round %d: %w", r, err)
		}
	}
	return sent, 0, nil
}

func testConcurrentWrites(t *testing.T, h Harness) {
	const writers, each = 4, 16
	pl := h.peer()
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

func testRedial(t *testing.T, h Harness) {
	pl := h.peer()
	e := newEnv(t, h, pl)
	_, oldServer := e.connect(pl)
	client := e.dial(pl)
	client.write([]byte("redialed"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type acceptResult struct {
		l   transport.Link
		id  transport.Identity
		err error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		l, id, err := e.listener.Accept(ctx)
		accepted <- acceptResult{l, id, err}
	}()
	// Either the old link carries on, following the dialer, or a new one
	// replaces it.
	var server *link
	select {
	case p := <-oldServer.packets:
		if !bytes.Equal(p, []byte("redialed")) {
			t.Fatalf("old link got %q", p)
		}
		server = oldServer
		cancel()
		if r := <-accepted; r.err == nil {
			t.Fatalf("a second link from %s while the first carries on", r.id)
		}
	case r := <-accepted:
		if r.err != nil || r.id != pl.Peer {
			t.Fatalf("accept after redial: %s, %v", r.id, r.err)
		}
		server = watch(t, r.l)
		server.expect([]byte("redialed"))
		oldServer.expectClosed(transport.ErrSuperseded)
	case <-time.After(wait):
		t.Fatal("the redialed link delivered nothing")
	}
	server.write([]byte("reply"))
	client.expect([]byte("reply"))
	e.expectNoAccept()
}

func testReplay(t *testing.T, h Harness) {
	if h.Interpose == nil {
		t.Skip("the transport has no wire to replay")
	}
	pl := h.peer()
	e := newEnv(t, h, pl)
	var replay func()
	e.dialTo, replay = h.Interpose(t, e.endpoint.Address)
	client, server := e.connect(pl)
	for i := range 5 {
		p := []byte(fmt.Sprintf("packet %d", i))
		client.write(p)
		server.expect(p)
	}
	replay()
	server.expectNothing()
	e.expectNoAccept()
	client.write([]byte("after the replay"))
	server.expect([]byte("after the replay"))
}

func testRevoked(t *testing.T, h Harness) {
	revoked, kept := h.peer(), h.peer()
	e := newEnv(t, h, revoked, kept)
	revokedClient, revokedServer := e.connect(revoked)
	keptClient, keptServer := e.connect(kept)

	e.table.Set(links(kept))
	revokedServer.expectClosed(transport.ErrRevoked)
	_ = revokedClient.WritePacket([]byte("still here?"))
	e.expectNoAccept()
	keptClient.write([]byte("kept"))
	keptServer.expect([]byte("kept"))

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if l, err := h.Dialer.Dial(ctx, e.dialTo, e.dialConfig(revoked)); err == nil {
		_ = watch(t, l).WritePacket([]byte("again"))
	}
	e.expectNoAccept()
}

func testCloseLink(t *testing.T, h Harness) {
	pl := h.peer()
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
	pl := h.peer()
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

func testListenerRestart(t *testing.T, h Harness) {
	pl := h.peer()
	e := newEnv(t, h, pl)
	client, _ := e.connect(pl)
	e.restart()
	// The dialer's link carries on with the new listener, or reports closed
	// so the layer above redials.
	if err := client.WritePacket([]byte("after restart")); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after the listener restarted: %v", err)
		}
		client = e.dial(pl)
		client.write([]byte("after restart"))
	}
	server, id := e.accept()
	if id != pl.Peer {
		t.Fatalf("accepted %s, want %s", id, pl.Peer)
	}
	server.expect([]byte("after restart"))
	for i := range 5 {
		p := []byte(fmt.Sprintf("from the new listener %d", i))
		server.write(p)
		client.expect(p)
	}
}

// testRevocationRacingDial revokes a credential while it is dialing and
// sending: whatever link it got must close, and no new one may open.
func testRevocationRacingDial(t *testing.T, h Harness) {
	kept := h.peer()
	e := newEnv(t, h, kept)
	for i := range 10 {
		pl := h.peer()
		e.table.Set(links(kept, pl))
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := h.Dialer.Dial(context.Background(), e.dialTo, e.dialConfig(pl))
			if err != nil {
				return
			}
			defer func() { _ = l.Close() }()
			for {
				_ = l.WritePacket([]byte("racing"))
				select {
				case <-stop:
					return
				case <-time.After(time.Millisecond):
				}
			}
		}()
		time.Sleep(time.Duration(i%5) * time.Millisecond)
		e.table.Set(links(kept))
		for {
			ctx, cancel := context.WithTimeout(context.Background(), quiet)
			l, id, err := e.listener.Accept(ctx)
			cancel()
			if err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("the listener died: %v", err)
				}
				break
			}
			if id != pl.Peer {
				t.Fatalf("accepted %s", id)
			}
			watch(t, l).expectClosed(transport.ErrRevoked)
		}
		// The drain ended with a quiet period while the dialer kept sending:
		// no new link opened.
		close(stop)
		wg.Wait()
	}
	client, server := e.connect(kept)
	server.write([]byte("kept"))
	client.expect([]byte("kept"))
}

// testCloseRacesLeakNothing closes links and listeners while packets are in
// flight both ways, and checks that every goroutine involved goes away.
func testCloseRacesLeakNothing(t *testing.T, h Harness) {
	base := settledGoroutines()
	for i := range 10 {
		pl := h.peer()
		e := newEnv(t, h, pl)
		client, server := e.connect(pl)
		var wg sync.WaitGroup
		flood := func(l *link) {
			defer wg.Done()
			for range 200 {
				if l.WritePacket([]byte("flood")) != nil {
					return
				}
			}
		}
		wg.Add(2)
		go flood(client)
		go flood(server)
		closers := []func(){
			func() { _ = server.Close() },
			func() { _ = e.listener.Close() },
			func() { _ = client.Close() },
		}
		for j := range closers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(time.Duration((i+j)%3) * time.Millisecond)
				closers[(i+j)%3]()
			}()
		}
		wg.Wait()
		server.expectClosed(nil)
		client.expectClosed(nil)
	}
	deadline := time.Now().Add(wait)
	for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base {
		buf := make([]byte, 1<<20)
		t.Fatalf("%d goroutines left over, %d before:\n%s", n, base, buf[:runtime.Stack(buf, true)])
	}
}

// settledGoroutines waits for the goroutine count to stop changing, so
// earlier tests' goroutines that are on their way out don't count.
func settledGoroutines() int {
	n := runtime.NumGoroutine()
	for range 50 {
		time.Sleep(20 * time.Millisecond)
		m := runtime.NumGoroutine()
		if m == n {
			return n
		}
		n = m
	}
	return n
}

func testAcceptContext(t *testing.T, h Harness) {
	e := newEnv(t, h, h.peer())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := e.listener.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("accept with an expiring context: %v, want context.DeadlineExceeded", err)
	}
}

func testDialDeadline(t *testing.T, h Harness) {
	pl := h.peer()
	e := newEnv(t, h, pl)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	start := time.Now()
	l, err := h.Dialer.Dial(ctx, e.dialTo, e.dialConfig(pl))
	if err == nil {
		_ = l.Close()
		t.Fatal("dialing with an expired context succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("dial with an expired context: %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > wait {
		t.Errorf("dial with an expired context took %v", time.Since(start))
	}
}

// testTableChangeKeepsLinks replaces the table with one that still holds a
// link's credential: the link stays open and keeps working.
func testTableChangeKeepsLinks(t *testing.T, h Harness) {
	pl := h.peer()
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	e.table.Set(links(h.peer(), pl, h.peer()))
	time.Sleep(20 * time.Millisecond)
	client.write([]byte("still here"))
	server.expect([]byte("still here"))
	server.write([]byte("me too"))
	client.expect([]byte("me too"))
	select {
	case err := <-server.err:
		t.Fatalf("the link closed on a table change that kept it: %v", err)
	default:
	}
}

// testWriteUnblocksOnClose writes as fast as possible with nobody reading,
// which blocks transports with backpressure, then closes the writing end:
// the writer must stop with net.ErrClosed. Transports whose writes never
// block pass trivially.
func testWriteUnblocksOnClose(t *testing.T, h Harness) {
	pl := h.peer()
	e := newEnv(t, h, pl)
	client := e.dial(pl)
	client.write([]byte("hello"))
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	server, _, err := e.listener.Accept(ctx) // accepted, never read
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	stopped := make(chan error, 1)
	go func() {
		p := make([]byte, 1024)
		for {
			if err := client.WritePacket(p); err != nil {
				stopped <- err
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	_ = client.Close()
	select {
	case err := <-stopped:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("writer stopped with %v, want net.ErrClosed", err)
		}
	case <-time.After(wait):
		t.Fatal("a write still blocked after Close")
	}
}

// testControlPackets sends packets marked as control both ways: whatever
// the transport does with their rhythm, they arrive as ordinary packets.
func testControlPackets(t *testing.T, h Harness) {
	pl := h.peer()
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	for i := range 3 {
		p := []byte(fmt.Sprintf("probe %d", i))
		if err := transport.WriteControl(client, p); err != nil {
			t.Fatalf("client: %v", err)
		}
		server.expect(p)
		if err := transport.WriteControl(server, p); err != nil {
			t.Fatalf("server: %v", err)
		}
		client.expect(p)
	}
}

// exchangeSizes sends packets of every interesting size both ways.
func exchangeSizes(client, server *link) {
	for _, size := range []int{1, 31, 32, 33, 148, 255, 1280, 1420, transport.MaxPacketSize} {
		up, down := randomPacket(size), randomPacket(size)
		client.write(up)
		server.expect(up)
		server.write(down)
		client.expect(down)
	}
}

// testShapingOneSided shapes one end of a link only: receivers undo
// shaping from the wire alone, so the ends need not agree.
func testShapingOneSided(t *testing.T, h Harness) {
	if h.Shaping.IsZero() {
		t.Skip("no shaping to apply")
	}
	t.Run("dialer", func(t *testing.T) {
		pl := h.peer()
		pl.Shaping = transport.Shaping{}
		e := newEnv(t, h, pl)
		client, server := e.connect(pl)
		exchangeSizes(client, server)
	})
	t.Run("listener", func(t *testing.T) {
		hz := h
		hz.Shaping = transport.Shaping{}
		pl := hz.peer()
		pl.Shaping = h.Shaping
		e := newEnv(t, hz, pl)
		client, server := e.connect(pl)
		exchangeSizes(client, server)
	})
}

// testShapingChange changes the listening end's shaping in its table: the
// link stays open and carries on, shaped anew.
func testShapingChange(t *testing.T, h Harness) {
	if h.Shaping.IsZero() {
		t.Skip("no shaping to apply")
	}
	pl := h.peer()
	e := newEnv(t, h, pl)
	client, server := e.connect(pl)
	for _, s := range []transport.Shaping{{}, h.Shaping} {
		changed := pl
		changed.Shaping = s
		e.table.Set(links(changed))
		time.Sleep(20 * time.Millisecond)
		exchangeSizes(client, server)
	}
	select {
	case err := <-server.err:
		t.Fatalf("the link closed on a shaping change: %v", err)
	default:
	}
	e.expectNoAccept()
}

// invalidShapings make no sense on any transport.
func invalidShapings() []transport.Shaping {
	return []transport.Shaping{
		{Padding: Buckets(512, 256)},
		{Padding: transport.Padding{Mode: transport.PadRandom, Min: 9, Max: 3}},
		{Padding: transport.Padding{Mode: 99}},
		{Jitter: -time.Millisecond},
		{BatchWindow: 2 * transport.MaxShapingDelay},
		{CoverInterval: time.Microsecond},
	}
}

// testShapingRefused asks for shaping the adapter can't honour, at either
// end: the dial fails, the listener skips the peer link (and accepts it
// once its shaping is fixed), the Check methods say so, and a live link
// changed to it closes with ErrSettingsRefused. Nothing is ever shaped
// less than asked.
func testShapingRefused(t *testing.T, h Harness) {
	for i, s := range append(invalidShapings(), h.Refused...) {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			refused := func(err error) bool {
				return errors.Is(err, transport.ErrInvalidShaping) || errors.Is(err, transport.ErrUnsupportedShaping)
			}
			good := h.peer()
			e := newEnv(t, h, good)
			cfg := e.dialConfig(good)
			cfg.Shaping = s
			ctx, cancel := context.WithTimeout(context.Background(), wait)
			defer cancel()
			if l, err := h.Dialer.Dial(ctx, e.dialTo, cfg); !refused(err) {
				if l != nil {
					_ = l.Close()
				}
				t.Fatalf("dial with shaping %+v: %v, want it refused", s, err)
			}
			if h.Transport != nil {
				if err := h.Transport.CheckEndpoint(e.dialTo, cfg); !refused(err) {
					t.Errorf("CheckEndpoint with shaping %+v: %v, want it refused", s, err)
				}
				bad := good.PeerLink
				bad.Shaping = s
				if err := h.Transport.CheckInbound(bad); !refused(err) {
					t.Errorf("CheckInbound with shaping %+v: %v, want it refused", s, err)
				}
			}

			// The listening end asked for it: the peer link is skipped.
			bad := h.peer()
			bad.Shaping = s
			e.table.Set(links(good, bad))
			time.Sleep(20 * time.Millisecond)
			if l, err := h.Dialer.Dial(ctx, e.dialTo, e.dialConfig(bad)); err == nil {
				_ = watch(t, l).WritePacket([]byte("shape me"))
			}
			e.expectNoAccept()
			client, server := e.connect(good)
			server.write([]byte("still serving"))
			client.expect([]byte("still serving"))

			// Positive control: the same peer link with shaping the
			// adapter takes is accepted, so the shaping was the reason.
			fixed := bad
			fixed.Shaping = h.Shaping
			e.table.Set(links(good, fixed))
			fixedClient, fixedServer := e.connectAdmitted(fixed)
			fixedServer.write([]byte("accepted"))
			fixedClient.expect([]byte("accepted"))

			// A live link whose shaping changes to s closes, saying why,
			// while its credential stays in the table.
			refusedNow := fixed
			refusedNow.Shaping = s
			e.table.Set(links(good, refusedNow))
			fixedServer.expectClosed(transport.ErrSettingsRefused)
			client.write([]byte("unaffected"))
			server.expect([]byte("unaffected"))
		})
	}
}

// testOverhead checks the MTU budget: shaping never lowers Overhead, and
// MaxPacket keeps padded packets within the unit size.
func testOverhead(t *testing.T, h Harness) {
	if h.Transport == nil {
		t.Skip("no Transport in the harness")
	}
	base, shaped := h.Transport.Overhead(transport.Shaping{}), h.Transport.Overhead(h.Shaping)
	if base < 0 || shaped < base {
		t.Fatalf("Overhead %d unshaped, %d shaped", base, shaped)
	}
	for _, unit := range []int{576, 1232, 1452, 1472} {
		got := transport.MaxPacket(h.Transport, h.Shaping, unit)
		if got < 0 || got > max(unit-shaped, 0) {
			t.Errorf("MaxPacket for %d-byte units: %d, Overhead %d", unit, got, shaped)
		}
		if p := h.Shaping.Padding; got > 0 && p.Mode == transport.PadToBuckets && p.Size(got+shaped) > unit {
			t.Errorf("MaxPacket for %d-byte units: %d, which pads to %d", unit, got, p.Size(got+shaped))
		}
	}
}
