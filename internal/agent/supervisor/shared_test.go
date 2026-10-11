package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
)

const (
	wait  = 5 * time.Second
	quiet = 300 * time.Millisecond
)

// fakeWorker is a worker in this process: its "sockets" queue what the
// supervisor forwards for a udp Listener (ListenForwarded) and send its
// replies back through the supervisor, as the real data socket does.
type fakeWorker struct {
	s     *shared
	space transport.SpaceID
	in    chan forwardedDatagram
	full  atomic.Bool // the worker is stuck: its socket is full
	got   atomic.Int64
	// streams gets the connections handed over, rebuilt from the passed
	// descriptor as the real worker does.
	streams chan handedStream

	closeOnce sync.Once
	done      chan struct{}
}

type forwardedDatagram struct {
	h ipc.DatagramHeader
	d []byte
}

type handedStream struct {
	listener uint32
	conn     net.Conn
	consumed []byte
}

func newFakeWorker(s *shared, space transport.SpaceID) *fakeWorker {
	return &fakeWorker{s: s, space: space, in: make(chan forwardedDatagram, 1024), streams: make(chan handedStream, 16), done: make(chan struct{})}
}

func (w *fakeWorker) sockets() *workerSockets { return &workerSockets{data: w, control: w} }

func (w *fakeWorker) TrySendDatagram(h ipc.DatagramHeader, d []byte) error {
	if w.full.Load() {
		return ipc.ErrFull
	}
	select {
	case w.in <- forwardedDatagram{h, bytes.Clone(d)}:
		w.got.Add(1)
		return nil
	default:
		return ipc.ErrFull
	}
}

func (w *fakeWorker) TrySend(m ipc.Message) error {
	id, f, consumed, err := ipc.DecodeStream(m)
	if err != nil {
		return err
	}
	conn, err := net.FileConn(f) // a descriptor of its own, as SCM_RIGHTS gives
	if err != nil {
		return err
	}
	w.streams <- handedStream{id, conn, bytes.Clone(consumed)}
	return nil
}

// The worker's view of the public socket, for udp's ListenForwarded.
func (w *fakeWorker) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case f := <-w.in:
		return copy(p, f.d), net.UDPAddrFromAddrPort(f.h.Remote), nil
	case <-w.done:
		return 0, nil, net.ErrClosed
	}
}

func (w *fakeWorker) WriteTo(p []byte, addr net.Addr) (int, error) {
	// The worker can only name a listener it was forwarded from; the fake
	// serves the first one.
	var id uint32
	for k := range *w.s.byID.Load() {
		id = max(id, k)
	}
	w.s.reply(w.space, ipc.DatagramHeader{Listener: id, Remote: addr.(*net.UDPAddr).AddrPort()}, p)
	return len(p), nil
}

func (w *fakeWorker) Close() error {
	w.closeOnce.Do(func() { close(w.done) })
	return nil
}

func (w *fakeWorker) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (w *fakeWorker) SetDeadline(time.Time) error      { return nil }
func (w *fakeWorker) SetReadDeadline(time.Time) error  { return nil }
func (w *fakeWorker) SetWriteDeadline(time.Time) error { return nil }

func newTestShared(t *testing.T, fair FairShare, transports ...transport.Transport) *shared {
	t.Helper()
	if len(transports) == 0 {
		transports = []transport.Transport{udp.New(udp.Options{})}
	}
	reg, err := transport.NewRegistry(transports...)
	if err != nil {
		t.Fatal(err)
	}
	s := newShared(reg, fair, slog.New(slog.DiscardHandler), time.Now)
	t.Cleanup(s.close)
	return s
}

func listenUDP(t *testing.T, s *shared, camo transport.Camouflage) string {
	t.Helper()
	if _, err := s.setListeners(context.Background(), []Listener{{Transport: udp.Name, Address: "127.0.0.1:0", Camouflage: camo}}); err != nil {
		t.Fatal(err)
	}
	for _, pl := range *s.byID.Load() {
		return pl.pc.LocalAddr().String()
	}
	t.Fatal("no listener")
	return ""
}

func randomSpace() transport.SpaceID {
	var id transport.SpaceID
	_, _ = rand.Read(id[:])
	return id
}

// serve runs a worker's udp listener on w for space's links.
func serve(t *testing.T, w *fakeWorker, links ...transport.PeerLink) transport.Listener {
	t.Helper()
	l := udp.New(udp.Options{}).ListenForwarded(w, transport.ListenConfig{Peers: transport.NewPeerTable(links...)})
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func dial(t *testing.T, address string, p transporttest.Peer) transport.Link {
	t.Helper()
	l, err := udp.New(udp.Options{}).Dial(context.Background(), address, transport.DialConfig{Credential: p.Credential})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func accept(t *testing.T, l transport.Listener) (transport.Link, transport.Identity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	link, id, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return link, id
}

func expectNoAccept(t *testing.T, l transport.Listener) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), quiet)
	defer cancel()
	if _, id, err := l.Accept(ctx); err == nil {
		t.Fatalf("accepted a link of %s", id)
	}
}

func read(t *testing.T, l transport.Link) string {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, transport.MaxPacketSize)
		n, err := l.ReadPacket(buf)
		ch <- result{buf[:n], err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return string(r.b)
	case <-time.After(wait):
		t.Fatal("nothing to read")
		return ""
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Two spaces behind one public socket: each worker gets only its own
// space's links, each link's space is the one its table was listed under
// (not what the entry said), and replies reach the dialers.
func TestWorkersGetOnlyTheirOwnLinks(t *testing.T) {
	camo := &transporttest.Recorder{}
	s := newTestShared(t, nil)
	address := listenUDP(t, s, camo)
	spaceA, spaceB := randomSpace(), randomSpace()
	a, b := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	// b's entry claims space A; it is listed in B's map, so it is B's.
	b.Peer.Space = spaceA
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{
		spaceA: {udp.Name: {a.PeerLink}},
		spaceB: {udp.Name: {b.PeerLink}},
	})
	workers := map[transport.SpaceID]*fakeWorker{}
	listeners := map[transport.SpaceID]transport.Listener{}
	for space, p := range map[transport.SpaceID]transporttest.Peer{spaceA: a, spaceB: b} {
		w := newFakeWorker(s, space)
		workers[space] = w
		s.attach(space, w.sockets())
		pl := p.PeerLink
		pl.Peer.Space = space // the worker's own map stamps its own space
		listeners[space] = serve(t, w, pl)
	}

	stranger := transporttest.SymmetricPeer()
	dialers := map[transport.SpaceID]transport.Link{}
	for space, p := range map[transport.SpaceID]transporttest.Peer{spaceA: a, spaceB: b} {
		dialers[space] = dial(t, address, p)
		if err := dialers[space].WritePacket([]byte("hello " + space.String())); err != nil {
			t.Fatal(err)
		}
	}
	if err := dial(t, address, stranger).WritePacket([]byte("let me in")); err != nil {
		t.Fatal(err)
	}
	for space, l := range listeners {
		link, id := accept(t, l)
		if id.Space != space {
			t.Fatalf("worker of %s accepted %s", space, id)
		}
		if got := read(t, link); got != "hello "+space.String() {
			t.Fatalf("worker of %s read %q", space, got)
		}
		if err := link.WritePacket([]byte("reply " + space.String())); err != nil {
			t.Fatal(err)
		}
		if got := read(t, dialers[space]); got != "reply "+space.String() {
			t.Fatalf("dialer of %s read %q", space, got)
		}
		expectNoAccept(t, l)
	}
	eventually(t, "the stranger reaching the camouflage", func() bool { return camo.Calls() == 1 })
	for space, w := range workers {
		if got := w.got.Load(); got != 1 {
			t.Errorf("worker of %s was forwarded %d datagrams, want 1", space, got)
		}
		if c := s.counters(space); c.Forwarded != 1 || c.Replies != 1 || c.RepliesRefused != 0 {
			t.Errorf("space %s: %+v", space, c)
		}
	}
	if li := s.infos(); len(li) != 1 || li[0].Routed != 2 || li[0].Unauthenticated != 1 {
		t.Errorf("listener: %+v", li)
	}
}

// Nothing that fails authentication is forwarded: unknown credentials,
// forgeries, junk, and a space with no map entry for the transport.
func TestBadCredentialsNeverReachAWorker(t *testing.T) {
	camo := &transporttest.Recorder{}
	s := newTestShared(t, nil)
	address := listenUDP(t, s, camo)
	space := randomSpace()
	good := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {good.PeerLink}}})
	w := newFakeWorker(s, space)
	s.attach(space, w.sockets())

	sent := 0
	// A dialer with an unknown secret.
	if err := dial(t, address, transporttest.SymmetricPeer()).WritePacket([]byte("x")); err != nil {
		t.Fatal(err)
	}
	sent++
	// Junk of every size around the transport's.
	raw, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	for _, n := range []int{1, 16, udp.Overhead, udp.Overhead + 100, 1400} {
		junk := make([]byte, n)
		_, _ = rand.Read(junk)
		if _, err := raw.Write(junk); err != nil {
			t.Fatal(err)
		}
		sent++
	}
	// A real datagram of the good peer, with one bit flipped: capture it
	// on the way by listening on a socket of our own.
	capture, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = capture.Close() }()
	if err := dial(t, capture.LocalAddr().String(), good).WritePacket([]byte("genuine")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = capture.SetReadDeadline(time.Now().Add(wait))
	n, _, err := capture.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		forged := bytes.Clone(buf[:n])
		forged[i] ^= 0x10
		if _, err := raw.Write(forged); err != nil {
			t.Fatal(err)
		}
		sent++
	}
	eventually(t, "everything reaching the camouflage", func() bool { return camo.Calls() == int64(sent) })
	if got := w.got.Load(); got != 0 {
		t.Fatalf("the worker was forwarded %d unauthenticated datagrams", got)
	}
	// The genuine one goes through, so the forgeries weren't refused for
	// another reason.
	if _, err := raw.Write(buf[:n]); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the genuine datagram", func() bool { return w.got.Load() == 1 })
}

// A stuck worker (its socket full) loses its own space's datagrams, and the
// other space's flow on the same public socket goes on.
func TestAStuckWorkerStallsOnlyItsSpace(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	stuck, live := randomSpace(), randomSpace()
	ps, pl := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{stuck: {udp.Name: {ps.PeerLink}}, live: {udp.Name: {pl.PeerLink}}})
	ws, wl := newFakeWorker(s, stuck), newFakeWorker(s, live)
	ws.full.Store(true)
	s.attach(stuck, ws.sockets())
	s.attach(live, wl.sockets())
	l := serve(t, wl, pl.PeerLink)
	ds, dl := dial(t, address, ps), dial(t, address, pl)

	link, _ := accept(t, func() transport.Listener {
		_ = dl.WritePacket([]byte("first"))
		return l
	}())
	if got := read(t, link); got != "first" {
		t.Fatalf("read %q", got)
	}
	for i := range 2000 {
		_ = ds.WritePacket([]byte("to the stuck worker"))
		if i%100 == 0 {
			if err := dl.WritePacket([]byte("still here")); err != nil {
				t.Fatal(err)
			}
			if got := read(t, link); got != "still here" {
				t.Fatalf("read %q", got)
			}
		}
	}
	eventually(t, "the stuck worker's drops", func() bool { return s.counters(stuck).WorkerFull > 0 })
	if c := s.counters(stuck); c.Forwarded != 0 {
		t.Fatalf("stuck space: %+v", c)
	}
}

type meter struct {
	mu      sync.Mutex
	allow   bool
	charged map[transport.SpaceID]int
}

func (m *meter) Allow(transport.SpaceID, int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allow
}

func (m *meter) Charge(space transport.SpaceID, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.charged[space] += n
}

func (m *meter) of(space transport.SpaceID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.charged[space]
}

func (m *meter) set(allow bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allow = allow
}

// A space's fair share is charged only for what its worker's socket took
// and what it sent; datagrams it refuses never reach the worker, and
// unauthenticated ones and a full socket cost nothing.
func TestFairShareChargedAfterTheWorkerAccepts(t *testing.T) {
	m := &meter{allow: true, charged: map[transport.SpaceID]int{}}
	s := newTestShared(t, m)
	address := listenUDP(t, s, nil)
	space := randomSpace()
	p := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}})
	w := newFakeWorker(s, space)
	s.attach(space, w.sockets())
	l := serve(t, w, p.PeerLink)
	d := dial(t, address, p)

	if err := d.WritePacket(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	link, _ := accept(t, l)
	read(t, link)
	if got := m.of(space); got != 1000+udp.Overhead {
		t.Fatalf("charged %d after one datagram, want %d", got, 1000+udp.Overhead)
	}
	if err := link.WritePacket(make([]byte, 500)); err != nil {
		t.Fatal(err)
	}
	read(t, d)
	if got := m.of(space); got != 1500+2*udp.Overhead {
		t.Fatalf("charged %d after the reply, want %d", got, 1500+2*udp.Overhead)
	}
	if err := dial(t, address, transporttest.SymmetricPeer()).WritePacket(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	w.full.Store(true)
	if err := d.WritePacket(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the full socket's drop", func() bool { return s.counters(space).WorkerFull == 1 })
	w.full.Store(false)
	m.set(false)
	if err := d.WritePacket(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the refusal", func() bool { return s.counters(space).OverShare == 1 })
	if got := m.of(space); got != 1500+2*udp.Overhead {
		t.Fatalf("charged %d, want only what went through", got)
	}
	if got := w.got.Load(); got != 1 {
		t.Fatalf("the worker was forwarded %d datagrams, want 1", got)
	}
}

// A worker may only answer: a datagram to anyone its space's authenticated
// datagrams didn't come from, or through a listener it wasn't forwarded
// from, never leaves the public socket.
func TestWorkersOnlyAnswer(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	space, other := randomSpace(), randomSpace()
	p, q := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}, other: {udp.Name: {q.PeerLink}}})
	w := newFakeWorker(s, space)
	s.attach(space, w.sockets())
	s.attach(other, newFakeWorker(s, other).sockets())
	l := serve(t, w, p.PeerLink)

	victim, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Close() }()
	// The other space's dialer: authenticated, but not this space's.
	if err := dial(t, address, q).WritePacket([]byte("other")); err != nil {
		t.Fatal(err)
	}
	if err := dial(t, address, p).WritePacket([]byte("mine")); err != nil {
		t.Fatal(err)
	}
	accept(t, l)
	eventually(t, "the other space's datagram", func() bool { return s.counters(other).Forwarded == 1 })
	listener := s.ipcListeners()[0].ID
	to := netip.MustParseAddrPort(victim.LocalAddr().String())
	var otherDialer netip.AddrPort
	for peer := range (*s.routes.Load())[other].peers {
		otherDialer = peer.remote
	}
	for _, h := range []ipc.DatagramHeader{
		{Listener: listener, Remote: to},              // a stranger
		{Listener: listener, Remote: otherDialer},     // another space's peer
		{Listener: listener + 1, Remote: otherDialer}, // a listener that doesn't exist
	} {
		s.reply(space, h, []byte("spam"))
	}
	if got := s.counters(space).RepliesRefused; got != 3 {
		t.Fatalf("%d replies refused, want 3", got)
	}
	_ = victim.SetReadDeadline(time.Now().Add(quiet))
	if _, _, err := victim.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("a worker reached someone who never wrote to it")
	}
}

// Datagrams for a space whose worker isn't running (between restarts) are
// dropped and counted, and flow again once the next incarnation attaches;
// a detached incarnation never gets more.
func TestRoutesFollowTheCurrentIncarnation(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	space := randomSpace()
	p := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}})
	d := dial(t, address, p)

	if err := d.WritePacket([]byte("nobody home")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the drop", func() bool { return s.counters(space).NoWorker == 1 })
	first := newFakeWorker(s, space)
	detach := s.attach(space, first.sockets())
	if err := d.WritePacket([]byte("one")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the first incarnation", func() bool { return first.got.Load() == 1 })
	second := newFakeWorker(s, space)
	detach()
	s.attach(space, second.sockets())
	detach() // the old incarnation's late cleanup leaves the new one attached
	if err := d.WritePacket([]byte("two")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the second incarnation", func() bool { return second.got.Load() == 1 })
	if first.got.Load() != 1 {
		t.Fatal("a detached incarnation was forwarded more")
	}
	// A space that left is unreachable at once.
	s.setSpaces(nil)
	if err := d.WritePacket([]byte("three")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the listener's refusal", func() bool { return s.infos()[0].Unauthenticated == 1 })
	if second.got.Load() != 1 {
		t.Fatal("a space that left was forwarded more")
	}
}

// One secret listed by two spaces is nobody's: both entries are dropped and
// reported, rather than one space guessed.
func TestASecretTwoSpacesShareIsRefused(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	a, b := randomSpace(), randomSpace()
	p := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{a: {udp.Name: {p.PeerLink}}, b: {udp.Name: {p.PeerLink}}})
	wa, wb := newFakeWorker(s, a), newFakeWorker(s, b)
	s.attach(a, wa.sockets())
	s.attach(b, wb.sockets())
	if err := dial(t, address, p).WritePacket([]byte("whose?")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the refusal", func() bool { return s.infos()[0].Unauthenticated == 1 })
	if wa.got.Load()+wb.got.Load() != 0 {
		t.Fatal("a shared secret was routed")
	}
	rejected := s.infos()[0].Rejected
	if len(rejected) != 2 || rejected[0].Peer.Space == rejected[1].Peer.Space {
		t.Fatalf("rejected %v, want both spaces' entries", rejected)
	}
}

func TestSetListenersKeepsWhatStays(t *testing.T) {
	s := newTestShared(t, nil)
	keep := Listener{Transport: udp.Name, Address: "127.0.0.1:0"}
	if _, err := s.setListeners(context.Background(), []Listener{keep}); err != nil {
		t.Fatal(err)
	}
	first := s.ipcListeners()
	if changed, err := s.setListeners(context.Background(), []Listener{keep}); err != nil || changed {
		t.Fatalf("the same set: changed %v, %v", changed, err)
	}
	if again := s.ipcListeners(); len(again) != 1 || again[0] != first[0] {
		t.Fatalf("listeners %v, then %v", first, again)
	}
	changed, err := s.setListeners(context.Background(), []Listener{keep, {Transport: "carrier-pigeon", Address: "127.0.0.1:0"}})
	if err == nil || changed {
		t.Fatalf("an unknown transport: changed %v, %v", changed, err)
	}
	if _, err := s.setListeners(context.Background(), []Listener{keep, keep}); err == nil {
		t.Fatal("a listener listed twice")
	}
	if changed, err := s.setListeners(context.Background(), nil); err != nil || !changed || len(s.ipcListeners()) != 0 {
		t.Fatalf("no listeners: changed %v, %v, %v", changed, err, s.ipcListeners())
	}
}

// Behind the supervisor's shared listener, udp passes the conformance
// suite: every space's links reach the one in-process worker serving them
// all, and its replies leave through the public socket.
func TestConformanceBehindTheSupervisor(t *testing.T) {
	tr := udp.New(udp.Options{})
	transporttest.Run(t, transporttest.Harness{
		Listen: func(t *testing.T, address string, peers transport.Peers, camouflage transport.Camouflage) (transport.Listener, transporttest.Endpoint) {
			if address == "" {
				address = "127.0.0.1:0"
			}
			reg, _ := transport.NewRegistry(tr)
			s := newShared(reg, nil, slog.New(slog.DiscardHandler), time.Now)
			if _, err := s.setListeners(context.Background(), []Listener{{Transport: udp.Name, Address: address, Camouflage: camouflage}}); err != nil {
				t.Fatal(err)
			}
			w := newFakeWorker(s, transport.SpaceID{})
			// The suite's peers each have a space of their own; the one
			// worker serves them all, and follows the table's changes.
			follow := func(links []transport.PeerLink) {
				bySpace := map[transport.SpaceID]map[string][]transport.PeerLink{}
				for _, pl := range links {
					if bySpace[pl.Peer.Space] == nil {
						bySpace[pl.Peer.Space] = map[string][]transport.PeerLink{}
					}
					bySpace[pl.Peer.Space][udp.Name] = append(bySpace[pl.Peer.Space][udp.Name], pl)
				}
				s.setSpaces(bySpace)
				for space := range bySpace {
					s.attach(space, w.sockets())
				}
			}
			links, changed := peers.Snapshot()
			follow(links)
			go func() {
				for {
					select {
					case <-w.done:
						return
					case <-changed:
					}
					links, changed = peers.Snapshot()
					follow(links)
				}
			}()
			l := tr.ListenForwarded(&closingWorker{fakeWorker: w, s: s}, transport.ListenConfig{Peers: peers, Camouflage: camouflage})
			var public string
			for _, pl := range *s.byID.Load() {
				public = pl.pc.LocalAddr().String()
			}
			return l, transporttest.Endpoint{Address: public}
		},
		Dialer: tr.Dialer(),
	})
}

// closingWorker takes the node down with the worker's listener, as the
// suite expects of a listener.
type closingWorker struct {
	*fakeWorker
	s *shared
}

func (c *closingWorker) Close() error {
	_ = c.fakeWorker.Close()
	c.s.close()
	return nil
}

// lineTransport is a stream transport for the handoff's tests: a
// connection starts with its credential and a newline.
type lineTransport struct{}

func (lineTransport) Name() string                                     { return "line" }
func (lineTransport) Dialer() transport.Dialer                         { return nil }
func (lineTransport) Overhead(transport.Shaping) int                   { return 0 }
func (lineTransport) CheckEndpoint(string, transport.DialConfig) error { return nil }
func (lineTransport) CheckInbound(transport.PeerLink) error            { return nil }
func (lineTransport) Listen(context.Context, transport.ListenConfig) (transport.Listener, error) {
	return nil, errors.ErrUnsupported
}
func (lineTransport) ListenStream(ctx context.Context, cfg transport.ListenConfig) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", cfg.Address)
}
func (lineTransport) Handoff(transport.ListenConfig) (transport.HandoffListener, error) {
	return nil, errors.ErrUnsupported
}
func (lineTransport) Router(peers transport.Peers) transport.Router { return lineRouter{peers} }

type lineRouter struct{ peers transport.Peers }

func (lineRouter) RouteDatagram([]byte) (transport.Identity, bool) {
	return transport.Identity{}, false
}

func (r lineRouter) RouteStream(conn net.Conn) (transport.Identity, []byte, bool) {
	line, err := bufio.NewReader(io.LimitReader(conn, 64)).ReadBytes('\n')
	if err != nil {
		return transport.Identity{}, line, false
	}
	links, _ := r.peers.Snapshot()
	for _, pl := range links {
		if bytes.Equal(pl.Verifier, bytes.TrimSuffix(line, []byte("\n"))) {
			return pl.Peer, line, true
		}
	}
	return transport.Identity{}, line, false
}

type streamCamouflage struct {
	got chan []byte
}

func (streamCamouflage) Datagram([]byte, net.Addr) {}
func (c streamCamouflage) Stream(conn net.Conn, consumed []byte) {
	_ = conn.Close()
	c.got <- consumed
}

// A stream connection goes, descriptor and consumed bytes, to its space's
// worker, which talks to the dialer on it; an unauthenticated one goes
// whole to the camouflage.
func TestStreamsAreHandedOver(t *testing.T) {
	s := newTestShared(t, nil, lineTransport{})
	camo := streamCamouflage{got: make(chan []byte, 4)}
	if _, err := s.setListeners(context.Background(), []Listener{{Transport: "line", Address: "127.0.0.1:0", Camouflage: camo}}); err != nil {
		t.Fatal(err)
	}
	var address string
	for _, pl := range *s.byID.Load() {
		address = pl.ln.Addr().String()
	}
	a, b := randomSpace(), randomSpace()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{
		a: {"line": {{Peer: transport.Identity{Node: transport.NodeID{1}}, Verifier: []byte("alpha")}}},
		b: {"line": {{Peer: transport.Identity{Node: transport.NodeID{2}}, Verifier: []byte("bravo")}}},
	})
	wa, wb := newFakeWorker(s, a), newFakeWorker(s, b)
	s.attach(a, wa.sockets())
	s.attach(b, wb.sockets())

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("bravo\nhello")); err != nil {
		t.Fatal(err)
	}
	var hs handedStream
	select {
	case hs = <-wb.streams:
	case hs = <-wa.streams:
		t.Fatal("space A's worker got space B's connection")
	case <-time.After(wait):
		t.Fatal("no handoff")
	}
	defer func() { _ = hs.conn.Close() }()
	if string(hs.consumed) != "bravo\n" || hs.listener != s.ipcListeners()[0].ID {
		t.Fatalf("handed over listener %d with %q", hs.listener, hs.consumed)
	}
	// The worker reads on where the router stopped, and answers.
	buf := make([]byte, 5)
	_ = hs.conn.SetReadDeadline(time.Now().Add(wait))
	if _, err := io.ReadFull(hs.conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("worker read %q, %v", buf, err)
	}
	if _, err := hs.conn.Write([]byte("welcome")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf = make([]byte, 7)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "welcome" {
		t.Fatalf("dialer read %q, %v", buf, err)
	}
	if c := s.counters(b); c.Streams != 1 {
		t.Fatalf("space B: %+v", c)
	}

	probe, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	if _, err := probe.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-camo.got:
		if string(got) != "GET / HTTP/1.1\r\n" {
			t.Fatalf("the camouflage got %q consumed", got)
		}
	case <-time.After(wait):
		t.Fatal("the probe never reached the camouflage")
	}
	select {
	case <-wa.streams:
		t.Fatal("a probe reached a worker")
	case <-wb.streams:
		t.Fatal("a probe reached a worker")
	case <-time.After(quiet):
	}
}
