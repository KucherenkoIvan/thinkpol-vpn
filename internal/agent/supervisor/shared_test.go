package supervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
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

	// For a worker serving every space (space zero): whose remote is whose.
	mu      sync.Mutex
	spaceOf map[netip.AddrPort]transport.SpaceID
}

// spaceSockets are a fake worker's sockets as one space's route sees them.
type spaceSockets struct {
	*fakeWorker
	space transport.SpaceID
}

func (s spaceSockets) TrySendDatagram(h ipc.DatagramHeader, d []byte) error {
	s.mu.Lock()
	s.spaceOf[h.Remote] = s.space
	s.mu.Unlock()
	return s.fakeWorker.TrySendDatagram(h, d)
}

func (w *fakeWorker) socketsOf(space transport.SpaceID) *workerSockets {
	ss := spaceSockets{w, space}
	return &workerSockets{data: ss, control: ss}
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
	return &fakeWorker{
		s: s, space: space, in: make(chan forwardedDatagram, 1024), streams: make(chan handedStream, 16), done: make(chan struct{}),
		spaceOf: map[netip.AddrPort]transport.SpaceID{},
	}
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
	remote := addr.(*net.UDPAddr).AddrPort()
	space := w.space
	if space == (transport.SpaceID{}) {
		w.mu.Lock()
		space = w.spaceOf[remote]
		w.mu.Unlock()
	}
	w.s.reply(space, ipc.DatagramHeader{Listener: id, Remote: remote}, p)
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
		return pl.udp.LocalAddr().String()
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
	l, err := udp.New(udp.Options{}).ListenForwarded(w, transport.Admission{Peers: transport.NewPeerTable(links...)})
	if err != nil {
		t.Fatal(err)
	}
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

func acceptLink(t *testing.T, l transport.Listener) (transport.Link, transport.Identity) {
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
		link, id := acceptLink(t, l)
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
		if c := s.counters(space); c.Forwarded != 1 || c.Replies != 1 || c.RepliesNotAllowed != 0 {
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
		if sent%16 == 0 { // in batches the socket has room for, so none is lost
			eventually(t, "a batch reaching the camouflage", func() bool { return camo.Calls() == int64(sent) })
		}
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

	link, _ := acceptLink(t, func() transport.Listener {
		_ = dl.WritePacket([]byte("first"))
		return l
	}())
	if got := read(t, link); got != "first" {
		t.Fatalf("read %q", got)
	}
	got := make(chan string, 64)
	go func() {
		buf := make([]byte, transport.MaxPacketSize)
		for {
			n, err := link.ReadPacket(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()
	// The flood can overflow the shared socket, which loses the live
	// space's datagram as often as the stuck one's: that's the network.
	// It is resent until it arrives; a stall would never let it through.
	stillHere := func(i int) {
		want := fmt.Sprintf("still here %d", i)
		for deadline := time.Now().Add(wait); time.Now().Before(deadline); {
			if err := dl.WritePacket([]byte(want)); err != nil {
				t.Fatal(err)
			}
			for resend := time.After(100 * time.Millisecond); ; {
				select {
				case g := <-got:
					if g == want {
						return
					}
					continue // an earlier one, resent
				case <-resend:
				}
				break
			}
		}
		t.Fatalf("%q never came through", want)
	}
	for i := range 2000 {
		_ = ds.WritePacket([]byte("to the stuck worker"))
		if i%100 == 0 {
			stillHere(i)
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
	link, _ := acceptLink(t, l)
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
	// A refused datagram from a new address leaves no address to answer.
	remotes := len((*s.routes.Load())[space].remotesForTest())
	if err := dial(t, address, p).WritePacket(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the second refusal", func() bool { return s.counters(space).OverShare == 2 })
	if n := len((*s.routes.Load())[space].remotesForTest()); n != remotes {
		t.Fatalf("%d addresses to answer after a refused datagram, want %d", n, remotes)
	}
	if got := m.of(space); got != 1500+2*udp.Overhead {
		t.Fatalf("charged %d, want only what went through", got)
	}
	if got := w.got.Load(); got != 1 {
		t.Fatalf("the worker was forwarded %d datagrams, want 1", got)
	}
}

// A worker may only answer: a datagram to anyone its own links' live
// datagrams didn't come from (a stranger, another space's dialer), or
// through a listener that isn't there, never leaves the public socket; a
// reply to its own dialer does.
func TestWorkersOnlyAnswer(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	space, other := randomSpace(), randomSpace()
	p, q := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}, other: {udp.Name: {q.PeerLink}}})
	w := newFakeWorker(s, space)
	s.attach(space, w.sockets())
	s.attach(other, newFakeWorker(s, other).sockets())

	victim, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Close() }()
	if err := dial(t, address, q).WritePacket([]byte("other")); err != nil {
		t.Fatal(err)
	}
	mine := dial(t, address, p)
	if err := mine.WritePacket([]byte("mine")); err != nil {
		t.Fatal(err)
	}
	var fromMine, fromOther ipc.DatagramHeader
	select {
	case f := <-w.in:
		fromMine = f.h
	case <-time.After(wait):
		t.Fatal("nothing forwarded")
	}
	eventually(t, "the other space's datagram", func() bool { return s.counters(other).Forwarded == 1 })
	for key := range (*s.routes.Load())[other].remotesForTest() {
		fromOther = ipc.DatagramHeader{Listener: key.listener, Remote: key.addr}
	}
	if !fromOther.Remote.IsValid() || fromOther.Remote == fromMine.Remote {
		t.Fatalf("the other dialer's address %v, mine %v", fromOther.Remote, fromMine.Remote)
	}
	to := netip.MustParseAddrPort(victim.LocalAddr().String())
	for _, h := range []ipc.DatagramHeader{
		{Listener: fromMine.Listener, Remote: to},               // a stranger
		{Listener: fromMine.Listener, Remote: fromOther.Remote}, // another space's peer
	} {
		s.reply(space, h, []byte("spam"))
	}
	s.reply(space, ipc.DatagramHeader{Listener: fromMine.Listener + 1, Remote: fromMine.Remote}, []byte("spam"))
	c := s.counters(space)
	if c.RepliesNotAllowed != 2 || c.RepliesNoListener != 1 || c.Replies != 0 {
		t.Fatalf("counters %+v, want 2 not allowed and 1 without a listener", c)
	}
	_ = victim.SetReadDeadline(time.Now().Add(quiet))
	if _, _, err := victim.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("a worker reached someone who never wrote to it")
	}
	// The same call, to its own dialer, goes out (named IPv4-mapped, too).
	mapped := netip.AddrPortFrom(netip.AddrFrom16(fromMine.Remote.Addr().As16()), fromMine.Remote.Port())
	s.reply(space, ipc.DatagramHeader{Listener: fromMine.Listener, Remote: mapped}, []byte("not a valid datagram"))
	if c := s.counters(space); c.Replies != 1 {
		t.Fatalf("a reply to the worker's own dialer: %+v", c)
	}
}

// answeringWorker answers every datagram before the supervisor's hand-off
// returns, as a worker process can.
type answeringWorker struct {
	*fakeWorker
}

func (w answeringWorker) TrySendDatagram(h ipc.DatagramHeader, d []byte) error {
	w.s.reply(w.space, h, []byte("answer"))
	return w.fakeWorker.TrySendDatagram(h, d)
}

// The worker is another process: its answer can reach the supervisor
// before forwarding the question has returned, and still goes out.
func TestAnAnswerMayBeatTheHandOff(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	space := randomSpace()
	p := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}})
	w := answeringWorker{newFakeWorker(s, space)}
	s.attach(space, &workerSockets{data: w, control: w})
	if err := dial(t, address, p).WritePacket([]byte("question")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the question forwarded", func() bool { return s.counters(space).Forwarded == 1 })
	if c := s.counters(space); c.Replies != 1 || c.RepliesNotAllowed != 0 {
		t.Fatalf("counters %+v, want the answer sent", c)
	}
}

// A replay of a link's genuine datagram, from anywhere, is dropped before
// it reaches the worker, costs its space nothing and gives the worker no
// new address to send to.
func TestReplaysCostNothing(t *testing.T) {
	m := &meter{allow: true, charged: map[transport.SpaceID]int{}}
	s := newTestShared(t, m)
	address := listenUDP(t, s, nil)
	space := randomSpace()
	p := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}})
	w := newFakeWorker(s, space)
	s.attach(space, w.sockets())

	// A passive tap's copy of a genuine datagram.
	capture, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = capture.Close() }()
	if err := dial(t, capture.LocalAddr().String(), p).WritePacket(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = capture.SetReadDeadline(time.Now().Add(wait))
	n, _, err := capture.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	genuine := buf[:n]
	var senders []net.Conn
	for range 3 {
		c, err := net.Dial("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write(genuine); err != nil {
			t.Fatal(err)
		}
		senders = append(senders, c)
		time.Sleep(20 * time.Millisecond)
	}
	eventually(t, "the replays counted", func() bool { return s.counters(space).Replayed == 2 })
	if w.got.Load() != 1 || m.of(space) != n {
		t.Fatalf("forwarded %d, charged %d: want the first only", w.got.Load(), m.of(space))
	}
	if remotes := (*s.routes.Load())[space].remotesForTest(); len(remotes) != 1 {
		t.Fatalf("remembered %v, want the first sender only", remotes)
	}
	listener := s.ipcListeners()[0].ID
	for _, c := range senders[1:] {
		s.reply(space, ipc.DatagramHeader{Listener: listener, Remote: netip.MustParseAddrPort(c.LocalAddr().String())}, []byte("x"))
	}
	if c := s.counters(space); c.RepliesNotAllowed != 2 {
		t.Fatalf("replies to the replayers: %+v", c)
	}
}

// remotesForTest lists the remote ends the space may answer.
func (r *route) remotesForTest() map[replyKey]netip.AddrPort {
	r.peers.mu.Lock()
	defer r.peers.mu.Unlock()
	out := map[replyKey]netip.AddrPort{}
	for k, rm := range r.peers.remotes {
		out[k] = rm.to
	}
	return out
}

// A link keeps its latest few remote ends; more evict its own oldest,
// never another link's; ends expire with the window.
func TestReplyPeersPerLink(t *testing.T) {
	r := &route{peers: newReplyPeers()}
	at := time.Unix(1_000_000, 0)
	addr := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), uint16(1000+i))
	}
	quietLink, busyLink := transport.NodeID{1}, transport.NodeID{2}
	r.peers.remember(quietLink, keyOf(1, addr(0)), addr(0), at)
	evicted := 0
	for i := 1; i <= 100; i++ {
		if r.peers.remember(busyLink, keyOf(1, addr(i)), addr(i), at.Add(time.Duration(i)*time.Millisecond)) {
			evicted++
		}
	}
	now := at.Add(time.Second)
	if _, ok := r.peers.replyTo(keyOf(1, addr(0)), now); !ok {
		t.Fatal("a busy link displaced another link's remote end")
	}
	for i := 1; i <= 100; i++ {
		if _, ok := r.peers.replyTo(keyOf(1, addr(i)), now); ok != (i > 100-replyPeersPerLink) {
			t.Fatalf("remote %d: allowed %v", i, ok)
		}
	}
	if got := evicted; got != 100-replyPeersPerLink {
		t.Fatalf("%d evictions reported, want %d", got, 100-replyPeersPerLink)
	}
	// Held by both links: kept until both let go.
	r.peers.remember(quietLink, keyOf(1, addr(100)), addr(100), now)
	for i := 200; i < 200+replyPeersPerLink; i++ {
		r.peers.remember(busyLink, keyOf(1, addr(i)), addr(i), now)
	}
	if _, ok := r.peers.replyTo(keyOf(1, addr(100)), now); !ok {
		t.Fatal("a remote end two links hold went with one of them")
	}
	// Expiry: refreshed ends stay, the rest go once the window passes.
	later := now.Add(replyWindow + replySweep)
	r.peers.remember(quietLink, keyOf(1, addr(0)), addr(0), later)
	if _, ok := r.peers.replyTo(keyOf(1, addr(0)), later); !ok {
		t.Fatal("a refreshed end expired")
	}
	if _, ok := r.peers.replyTo(keyOf(1, addr(200)), later); ok {
		t.Fatal("an end past the window still allowed")
	}
	if len(r.peers.links[busyLink].entriesForTest()) != 0 || len(r.peers.remotes) != 1 {
		t.Fatalf("after the sweep: %d remote ends left, want 1", len(r.peers.remotes))
	}
	// A link-local remote's zone is kept for the reply.
	zoned := netip.MustParseAddrPort("[fe80::1%eth0]:51820")
	r.peers.remember(quietLink, keyOf(1, zoned), zoned, later)
	if to, ok := r.peers.replyTo(keyOf(1, netip.MustParseAddrPort("[fe80::1]:51820")), later); !ok || to != zoned {
		t.Fatalf("a reply to a zoned remote goes to %v (%v)", to, ok)
	}
}

func (lr *linkRemotes) entriesForTest() []replyKey {
	if lr == nil {
		return nil
	}
	var out []replyKey
	for i := range lr.n {
		out = append(out, lr.entries[i].key)
	}
	return out
}

// One space's link churning through new source addresses as fast as it can
// (each a fresh, authenticated sender) doesn't hold up another space's
// traffic on the same socket; the churn stays within its own link's cap.
func TestASourceFloodStallsNoOtherSpace(t *testing.T) {
	s := newTestShared(t, nil)
	address := listenUDP(t, s, nil)
	noisy, calm := randomSpace(), randomSpace()
	pn, pc := transporttest.SymmetricPeer(), transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{noisy: {udp.Name: {pn.PeerLink}}, calm: {udp.Name: {pc.PeerLink}}})
	wn, wc := newFakeWorker(s, noisy), newFakeWorker(s, calm)
	s.attach(noisy, wn.sockets())
	s.attach(calm, wc.sockets())
	go func() { // the noisy worker drains, so its socket never fills
		for {
			select {
			case <-wn.in:
			case <-wn.done:
				return
			}
		}
	}()
	defer func() { _ = wn.Close() }()
	l := serve(t, wc, pc.PeerLink)
	d := dial(t, address, pc)
	_ = d.WritePacket([]byte("ping"))
	link, _ := acceptLink(t, l)
	read(t, link)

	stop := make(chan struct{})
	var sources atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := udp.New(udp.Options{})
			for {
				select {
				case <-stop:
					return
				default:
				}
				l, err := tr.Dial(context.Background(), address, transport.DialConfig{Credential: pn.Credential})
				if err != nil {
					continue
				}
				_ = l.WritePacket([]byte("new source"))
				_ = l.Close()
				sources.Add(1)
			}
		}()
	}
	// Ping-pong: the worker answers every ping it gets. Datagrams lost to
	// the flood (the shared socket's buffer overflowing is the network's
	// business, not the reply table's) are sent again after resend.
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := link.ReadPacket(buf)
			if err != nil {
				return
			}
			_ = link.WritePacket(buf[:n])
		}
	}()
	pongs := make(chan string, 16)
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := d.ReadPacket(buf)
			if err != nil {
				return
			}
			pongs <- string(buf[:n])
		}
	}()
	const resend = 50 * time.Millisecond
	var rtts []time.Duration
	lost := 0
	for i, begin := 0, time.Now(); time.Since(begin) < 2*time.Second; i++ {
		ping := fmt.Sprintf("ping %d", i)
		start := time.Now()
		for got := ""; got != ping; {
			if time.Since(start) > wait {
				t.Fatalf("%s never came back", ping)
			}
			if err := d.WritePacket([]byte(ping)); err != nil {
				t.Fatal(err)
			}
			select {
			case got = <-pongs:
			case <-time.After(resend):
				lost++
			}
		}
		rtts = append(rtts, time.Since(start))
	}
	close(stop)
	wg.Wait()
	slices.Sort(rtts)
	c := s.counters(noisy)
	p99 := rtts[len(rtts)*99/100]
	t.Logf("calm space round trips during a flood of %d new sources: median %v, p99 %v, max %v, %d of %d resent; the noisy link evicted %d of its own",
		sources.Load(), rtts[len(rtts)/2], p99, rtts[len(rtts)-1], lost, len(rtts), c.ReplyPeersEvicted)
	if n := len((*s.routes.Load())[noisy].remotesForTest()); n > replyPeersPerLink {
		t.Fatalf("the noisy link holds %d remote ends", n)
	}
	if sources.Load() > 2*replyPeersPerLink && c.ReplyPeersEvicted == 0 {
		t.Fatal("no eviction counted")
	}
	// Every ping came back (or the loop failed); a stall would show in the
	// median, not only in the resent tail. Unloaded, the median is well
	// under a millisecond, but on a machine busy with other tests the
	// scheduler alone can add tens of them, so the bound is the resend
	// interval: above it, most pings were stuck long enough to be sent
	// again, which is a stall, not a slow machine.
	if median := rtts[len(rtts)/2]; median > resend {
		t.Fatalf("the calm space's median round trip was %v", median)
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
			prev := map[transport.SpaceID]map[string][]transport.PeerLink{}
			follow := func(links []transport.PeerLink) {
				bySpace := map[transport.SpaceID]map[string][]transport.PeerLink{}
				for _, pl := range links {
					if bySpace[pl.Peer.Space] == nil {
						bySpace[pl.Peer.Space] = map[string][]transport.PeerLink{}
					}
					bySpace[pl.Peer.Space][udp.Name] = append(bySpace[pl.Peer.Space][udp.Name], pl)
				}
				// As the supervisor does: a new space's worker is attached
				// before its links authenticate; the others keep theirs.
				first := maps.Clone(prev)
				for space := range bySpace {
					if _, ok := first[space]; !ok {
						first[space] = nil
					}
				}
				s.setSpaces(first)
				for space := range bySpace {
					s.attach(space, w.socketsOf(space))
				}
				s.setSpaces(bySpace)
				prev = bySpace
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
			l, err := tr.ListenForwarded(&closingWorker{fakeWorker: w, s: s}, transport.Admission{Peers: peers, Camouflage: camouflage})
			if err != nil {
				t.Fatal(err)
			}
			var public string
			for _, pl := range *s.byID.Load() {
				public = pl.udp.LocalAddr().String()
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
func (lineTransport) Network() string                                  { return "tcp" }
func (lineTransport) CheckEndpoint(string, transport.DialConfig) error { return nil }
func (lineTransport) CheckInbound(transport.PeerLink) error            { return nil }
func (lineTransport) Listen(context.Context, transport.ListenConfig, transport.Admission) (transport.Listener, error) {
	return nil, errors.ErrUnsupported
}
func (lineTransport) ListenStream(ctx context.Context, cfg transport.ListenConfig) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", cfg.Address)
}
func (lineTransport) Handoff(transport.Admission) (transport.HandoffListener, error) {
	return nil, errors.ErrUnsupported
}
func (lineTransport) StreamRouter(peers transport.Peers) transport.StreamRouter {
	return lineRouter{peers}
}

type lineRouter struct{ peers transport.Peers }

func (lineRouter) Rejected() []transport.PeerError { return nil }

func (r lineRouter) RouteStream(conn net.Conn) (transport.Identity, []byte, bool) {
	// Byte by byte: whatever is read is consumed and must be reported.
	var line []byte
	b := make([]byte, 1)
	for len(line) < 64 && !bytes.HasSuffix(line, []byte("\n")) {
		if _, err := conn.Read(b); err != nil {
			return transport.Identity{}, line, false
		}
		line = append(line, b[0])
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

// A listener routes at most so many connections at once; the rest go
// straight to the camouflage, counted.
func TestStreamRoutingIsBounded(t *testing.T) {
	s := newTestShared(t, nil, lineTransport{})
	s.routingLimit = 2
	camo := streamCamouflage{got: make(chan []byte, 4)}
	if _, err := s.setListeners(context.Background(), []Listener{{Transport: "line", Address: "127.0.0.1:0", Camouflage: camo}}); err != nil {
		t.Fatal(err)
	}
	var address string
	for _, pl := range *s.byID.Load() {
		address = pl.ln.Addr().String()
	}
	for range 3 { // silent: they hold their routing slots
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
	}
	select {
	case got := <-camo.got:
		if len(got) != 0 {
			t.Fatalf("an overload went to the camouflage with %q consumed", got)
		}
	case <-time.After(wait):
		t.Fatal("the third connection wasn't turned away")
	}
	if li := s.infos(); li[0].StreamsOverloaded != 1 {
		t.Fatalf("listener %+v", li[0])
	}
}

// A credential's replay history spans every listener of its transport and
// survives a listener's reopening: a datagram captured on one listener and
// sent to another, or to the reopened one, is a replay.
func TestReplaysAcrossListeners(t *testing.T) {
	s := newTestShared(t, nil)
	a, b := Listener{Transport: udp.Name, Address: "127.0.0.1:0"}, Listener{Transport: udp.Name, Address: "[::1]:0"}
	if _, err := s.setListeners(context.Background(), []Listener{a, b}); err != nil {
		t.Fatal(err)
	}
	addrs := map[string]string{}
	for _, pl := range *s.byID.Load() {
		addrs[pl.cfg.Address] = pl.udp.LocalAddr().String()
	}
	space := randomSpace()
	p := transporttest.SymmetricPeer()
	s.setSpaces(map[transport.SpaceID]map[string][]transport.PeerLink{space: {udp.Name: {p.PeerLink}}})
	w := newFakeWorker(s, space)
	s.attach(space, w.sockets())

	capture, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = capture.Close() }()
	if err := dial(t, capture.LocalAddr().String(), p).WritePacket([]byte("once")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = capture.SetReadDeadline(time.Now().Add(wait))
	n, _, err := capture.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	genuine := buf[:n]
	send := func(to string) {
		t.Helper()
		c, err := net.Dial("udp", to)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write(genuine); err != nil {
			t.Fatal(err)
		}
	}
	send(addrs[a.Address])
	eventually(t, "the genuine datagram on A", func() bool { return w.got.Load() == 1 })
	send(addrs[b.Address])
	eventually(t, "the replay on B", func() bool { return s.counters(space).Replayed == 1 })
	// A reopened: a new socket, the same history.
	if _, err := s.setListeners(context.Background(), []Listener{b}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.setListeners(context.Background(), []Listener{a, b}); err != nil {
		t.Fatal(err)
	}
	for _, pl := range *s.byID.Load() {
		if pl.cfg.Address == a.Address {
			send(pl.udp.LocalAddr().String())
		}
	}
	eventually(t, "the replay on the reopened A", func() bool { return s.counters(space).Replayed == 2 })
	if w.got.Load() != 1 {
		t.Fatalf("forwarded %d, want the genuine datagram only", w.got.Load())
	}
	if remotes := (*s.routes.Load())[space].remotesForTest(); len(remotes) != 1 {
		t.Fatalf("remembered %v, want the genuine sender only", remotes)
	}
}
