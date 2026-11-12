package reality

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	xreality "github.com/xtls/reality"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
)

// sharedNode is a server node's shared listener in one process: the
// supervisor's public listener and router, and a handoff listener per
// space (its worker's), each connection the router hands over passed on
// as the supervisor passes it, as fresh descriptors, and served one after
// another, as a worker serves them.
type sharedNode struct {
	tr      *Transport
	ln      transport.StreamListener
	table   *transport.PeerTable // the router's
	workers map[transport.SpaceID]transport.HandoffListener
	// handed reports each handoff once its worker has it, verdicts every
	// connection's verdict.
	handed   chan transport.Identity
	verdicts chan transport.StreamVerdict
	// handoff, if set, replaces the listener's handoff settings.
	handoff []byte

	mu       sync.Mutex
	unserved map[transport.SpaceID]bool
}

// listenShared opens a public reality listener whose target is tg, with
// its router; serve starts routing.
func listenShared(t *testing.T, tr *Transport, tg *target, k keys) *sharedNode {
	t.Helper()
	table := transport.NewPeerTable()
	ln, err := tr.ListenStream(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, tg, 0)}, tr.StreamRouter(table))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &sharedNode{tr: tr, ln: ln, table: table, workers: map[transport.SpaceID]transport.HandoffListener{},
		handed: make(chan transport.Identity, 16), verdicts: make(chan transport.StreamVerdict, 64), unserved: map[transport.SpaceID]bool{}}
}

// startShared serves spaces' tables behind one reality listener whose
// target is tg.
func startShared(t *testing.T, tr *Transport, tg *target, k keys, spaces map[transport.SpaceID][]transport.PeerLink, routerTable ...transport.PeerLink) *sharedNode {
	t.Helper()
	n := listenShared(t, tr, tg, k)
	n.serve(t, spaces, routerTable...)
	return n
}

// serve gives each space a worker with its own table and the router the
// merged one, or routerTable when given, and routes.
func (n *sharedNode) serve(t *testing.T, spaces map[transport.SpaceID][]transport.PeerLink, routerTable ...transport.PeerLink) {
	t.Helper()
	var merged []transport.PeerLink
	for space, links := range spaces {
		for i := range links {
			links[i].Peer.Space = space
		}
		merged = append(merged, links...)
		settings := n.ln.HandoffSettings()
		if n.handoff != nil {
			settings = n.handoff
		}
		hl, err := n.tr.Handoff(n.addr(), settings, transport.Admission{Peers: transport.NewPeerTable(links...)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hl.Close() })
		n.workers[space] = hl
	}
	if routerTable != nil {
		merged = routerTable
	}
	n.table.Set(merged)
	queues := map[transport.SpaceID]chan transport.StreamHandoff{}
	for space, hl := range n.workers {
		q := make(chan transport.StreamHandoff, 16)
		queues[space] = q
		go func() {
			for h := range q {
				hl.ServeStream(h)
				n.handed <- h.Peer
			}
		}()
	}
	serves := func(peer transport.Identity) bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.workers[peer.Space] != nil && !n.unserved[peer.Space]
	}
	go func() {
		for {
			conn, err := n.ln.Accept()
			if err != nil {
				return
			}
			go func() {
				h, v := n.ln.RouteStream(conn, serves, nil)
				n.verdicts <- v
				if v != transport.StreamRouted {
					return
				}
				h.Conn, h.Target = redescribe(t, h.Conn), redescribe(t, h.Target)
				queues[h.Peer.Space] <- h
			}()
		}
	}()
}

// redescribe is c as a worker gets it: a new descriptor of the
// connection, the original closed.
func redescribe(t *testing.T, c net.Conn) net.Conn {
	t.Helper()
	f, err := c.(*net.TCPConn).File()
	if err != nil {
		t.Error(err)
		return c
	}
	_ = c.Close()
	defer func() { _ = f.Close() }()
	nc, err := net.FileConn(f)
	if err != nil {
		t.Error(err)
	}
	return nc
}

func (n *sharedNode) addr() string { return n.ln.Addr().String() }

func (n *sharedNode) stopServing(space transport.SpaceID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.unserved[space] = true
}

// verdict waits for the next connection's verdict.
func (n *sharedNode) verdict(t *testing.T) transport.StreamVerdict {
	t.Helper()
	select {
	case v := <-n.verdicts:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("no connection was decided")
		return 0
	}
}

func randomSpace() transport.SpaceID { return transporttest.RandomIdentity().Space }

// accept waits for l's next link.
func accept(t *testing.T, l transport.Listener) (transport.Link, transport.Identity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	link, id, err := l.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = link.Close() })
	return link, id
}

// The short id selects the space: a connection is handed to the worker of
// the space whose table lists its short id, which completes REALITY's
// handshake and carries packets both ways; the other worker sees nothing.
func TestTheShortIDSelectsTheSpacesWorker(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	idA, _ := shortIDs()
	idB, _ := shortIDs()
	a, b := randomSpace(), randomSpace()
	plA, plB := peerLink(idA), peerLink(idB)
	n := startShared(t, tr, theTarget(t), k, map[transport.SpaceID][]transport.PeerLink{a: {plA}, b: {plB}})

	for _, c := range []struct {
		id           []byte
		space, other transport.SpaceID
		node         transport.NodeID
	}{{idA, a, b, plA.Peer.Node}, {idB, b, a, plB.Peer.Node}} {
		client, err := dial(t, tr, n.addr(), k, c.id)
		if err != nil {
			t.Fatalf("dial for space %s: %v", c.space, err)
		}
		server, id := accept(t, n.workers[c.space])
		if id != (transport.Identity{Space: c.space, Node: c.node}) {
			t.Fatalf("space %s's worker accepted %s", c.space, id)
		}
		if err := client.WritePacket([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		if m, err := server.ReadPacket(buf); err != nil || string(buf[:m]) != "ping" {
			t.Fatalf("worker read %q, %v", buf[:m], err)
		}
		if err := server.WritePacket([]byte("pong")); err != nil {
			t.Fatal(err)
		}
		if m, err := client.ReadPacket(buf); err != nil || string(buf[:m]) != "pong" {
			t.Fatalf("dialer read %q, %v", buf[:m], err)
		}
		expectNoAccept(t, n.workers[c.other])
	}
}

// Behind a shared listener as on its own, a wrong short id, a replay and
// the short id of a space the node no longer serves are spliced to the
// target, raw and whole, and reach no worker; each verdict says which.
func TestWhatTheRouterRefusesIsSplicedWholeToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	gone, _ := shortIDs()
	a, b := randomSpace(), randomSpace()
	n := startShared(t, tr, theTarget(t), k, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}, b: {peerLink(gone)}})
	n.stopServing(b)

	t.Run("wrong short id", func(t *testing.T) {
		wrong, _ := shortIDs()
		tp := newTap(t, n.addr())
		if _, err := dial(t, tr, tp.addr(), k, wrong); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("dial: %v, want %v", err, ErrNotAuthenticated)
		}
		if v := n.verdict(t); v != transport.StreamUnknown {
			t.Errorf("verdict %d, want StreamUnknown", v)
		}
		if !splicedWhole(theTarget(t), tp) {
			t.Error("the target didn't receive exactly what the dialer sent")
		}
	})
	t.Run("a space not served", func(t *testing.T) {
		tp := newTap(t, n.addr())
		if _, err := dial(t, tr, tp.addr(), k, gone); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("dial: %v, want %v", err, ErrNotAuthenticated)
		}
		if v := n.verdict(t); v != transport.StreamUnserved {
			t.Errorf("verdict %d, want StreamUnserved", v)
		}
		if !splicedWhole(theTarget(t), tp) {
			t.Error("the target didn't receive exactly what the dialer sent")
		}
	})
	t.Run("replay", func(t *testing.T) {
		tp := newTap(t, n.addr())
		client, err := dial(t, tr, tp.addr(), k, id)
		if err != nil {
			t.Fatal(err)
		}
		if v := n.verdict(t); v != transport.StreamRouted {
			t.Fatalf("verdict %d, want StreamRouted", v)
		}
		server, _ := accept(t, n.workers[a])
		if err := client.WritePacket([]byte("before the replay")); err != nil {
			t.Fatal(err)
		}
		if _, err := server.ReadPacket(make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
		streams := tp.replay(t)
		if len(streams) != 1 {
			t.Fatalf("captured %d streams, want 1", len(streams))
		}
		if v := n.verdict(t); v != transport.StreamReplayed {
			t.Errorf("verdict %d, want StreamReplayed", v)
		}
		if !theTarget(t).receivedExactly(streams[0]) {
			t.Error("the replay wasn't spliced to the target raw and whole")
		}
	})
	for _, w := range n.workers {
		expectNoAccept(t, w) // past the replay's original, accepted above
	}
}

// A hello sealed before the second the router started in is refused, as
// stale, even though it is fresh and the router never saw it: after a
// supervisor restart, a tap's capture of what the old supervisor admitted
// is spliced to the target, not answered with REALITY's handshake.
func TestARouterRefusesHellosSealedBeforeItStarted(t *testing.T) {
	k := newKeys(t)
	key, err := ecdh.X25519().NewPrivateKey(k.private)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := shortIDs()
	a := randomSpace()
	start := time.Now()
	clock := func(at time.Time) func() time.Time {
		return func() time.Time { return at.Add(time.Since(start)) }
	}
	// The supervisor that admitted the hello, and its successor, started
	// two seconds later (both within the hello's window).
	before := startShared(t, newTransport(Options{Now: clock(start)}), theTarget(t), k, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})
	after := startShared(t, newTransport(Options{Now: clock(start.Add(2 * time.Second))}), theTarget(t), k, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})
	hello := helloRecord(t, key, shortID(id), uint32(start.Unix()))

	probe(t, before.addr(), hello)
	if v := before.verdict(t); v != transport.StreamRouted {
		t.Fatalf("the first supervisor's verdict %d, want StreamRouted", v)
	}
	probe(t, after.addr(), hello)
	if v := after.verdict(t); v != transport.StreamStale {
		t.Fatalf("its successor's verdict on the capture %d, want StreamStale", v)
	}
}

// A hello the router authenticated but the worker's own table doesn't
// list (its map changed in between) is spliced to the target by the
// worker, whole: the byte the router held back reaches the target once.
func TestAHandoffTheWorkerRefusesIsSplicedWholeToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	a := randomSpace()
	known := peerLink(id)
	known.Peer.Space = a
	n := startShared(t, tr, theTarget(t), k, map[transport.SpaceID][]transport.PeerLink{a: nil}, known)

	tp := newTap(t, n.addr())
	if _, err := dial(t, tr, tp.addr(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("dial: %v, want %v", err, ErrNotAuthenticated)
	}
	if !splicedWhole(theTarget(t), tp) {
		t.Error("the target didn't receive exactly what the dialer sent")
	}
	expectNoAccept(t, n.workers[a])
}

// The router's read deadline (the supervisor's bound on routing) passing
// before the hello is whole ends the routing, not the connection: it stays
// spliced to the target, which closes it when the site would. waiting is
// called once the mirror is up, before the hello is decided.
func TestARoutingDeadlineLeavesTheConnectionToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	tg := newIdleTarget(t, time.Second, nil)
	ln, err := tr.ListenStream(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, tg, 0)}, tr.StreamRouter(transport.NewPeerTable()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	waited := make(chan time.Duration, 1)
	routed := make(chan time.Duration, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		start := time.Now()
		_ = conn.SetReadDeadline(start.Add(200 * time.Millisecond))
		waiting := func() { waited <- time.Since(start) }
		if _, v := ln.RouteStream(conn, func(transport.Identity) bool { return true }, waiting); v != transport.StreamUnknown {
			t.Errorf("a partial hello's verdict %d", v)
		}
		routed <- time.Since(start)
	}()
	c := probe(t, ln.Addr().String(), []byte{recordTypeHandshake, 3, 1, 2, 0, 1})
	select {
	case d := <-waited:
		if d > 150*time.Millisecond {
			t.Errorf("waiting called %v after accept, not once the mirror was up", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting never called")
	}
	select {
	case d := <-routed:
		if d > 900*time.Millisecond {
			t.Fatalf("routing took %v, past its deadline", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("routing never ended")
	}
	if d := closedWithin(t, c, 5*time.Second); d < 500*time.Millisecond {
		t.Fatalf("closed %v after routing gave up, before the target's idle timeout", d)
	}
}

// Past the listener's bound on live splices a stranger is closed, as an
// overloaded site would close it, while those spliced stay with the
// target; a member's hello still gets its own slot and is handed over.
func TestPastTheSpliceBoundAStrangerIsClosedAndMembersAreRouted(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	a := randomSpace()
	n := listenShared(t, tr, newIdleTarget(t, time.Minute, nil), k)
	n.ln.(*publicListener).gate.splices = make(chan struct{}, 2)
	n.serve(t, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})

	var spliced []net.Conn
	for range 2 {
		spliced = append(spliced, probe(t, n.addr(), []byte("GET / HTTP/1.1\r\n\r\n")))
		if v := n.verdict(t); v != transport.StreamUnknown {
			t.Fatalf("a stranger's verdict %d", v)
		}
	}
	stranger := probe(t, n.addr(), []byte("GET / HTTP/1.1\r\n\r\n"))
	if d := closedWithin(t, stranger, 5*time.Second); d > 2*time.Second {
		t.Fatalf("the stranger past the bound was closed after %v", d)
	}
	if _, err := dial(t, tr, n.addr(), k, id); err != nil {
		t.Fatalf("a member past the bound: %v", err)
	}
	accept(t, n.workers[a])
	for _, c := range spliced {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
			t.Fatalf("a spliced stranger was dropped: %v", err)
		}
	}
}

// A fresh worker, whose REALITY has detected nothing, answers a member's
// handshake with the post-handshake records the target itself sends:
// Handoff puts what the supervisor learned where REALITY reads it.
// Settings missing a key are refused. (REALITY's detection verifies the
// target against the system roots, so it learns nothing from the
// self-signed fixture here: the test measures the target itself and puts
// that in the settings, as the supervisor's detection does in the lab.)
func TestHandoffPutsTheTargetsRecordsWhereREALITYReadsThem(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	tg := newGreetingTarget(t, make([]byte, 18), make([]byte, 13))
	id, _ := shortIDs()
	a := randomSpace()

	// What REALITY's detection dials with for h2, our dialer's ALPN.
	want := postHandshakeRecords(t, tg.addr(), func(address string) {
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		uc := utls.UClient(c, &utls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
		if err := uc.Handshake(); err != nil {
			t.Fatal(err)
		}
	})
	if len(want) == 0 {
		t.Fatal("the target sent no post-handshake records to compare")
	}

	n := listenShared(t, tr, tg, k)
	var hs handoffSettings
	if err := json.Unmarshal(n.ln.HandoffSettings(), &hs); err != nil {
		t.Fatal(err)
	}
	for key := range hs.Records {
		hs.Records[key] = want
		xreality.GlobalPostHandshakeRecordsLens.Delete(key) // as in a worker, which never detected
	}
	settings, err := json.Marshal(hs)
	if err != nil {
		t.Fatal(err)
	}
	n.handoff = settings
	n.serve(t, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})
	got := postHandshakeRecords(t, n.addr(), func(address string) {
		if _, err := dial(t, tr, address, k, id); err != nil {
			t.Fatal(err)
		}
		accept(t, n.workers[a])
	})
	if !slices.Equal(got, want) {
		t.Fatalf("the worker's post-handshake records %v, the target's %v", got, want)
	}

	for key := range hs.Records {
		delete(hs.Records, key)
		break
	}
	if settings, err = json.Marshal(hs); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Handoff(n.addr(), settings, transport.Admission{Peers: transport.NewPeerTable()}); !errors.Is(err, ErrSettings) {
		t.Fatalf("handoff settings missing a key: %v, want %v", err, ErrSettings)
	}
}

// postHandshakeRecords puts a record tap in front of address, runs
// handshake through it (given the tap's address), and returns the lengths of the
// records the far end sent after the dialer's Finished (its first
// application-data record), once it has been quiet for a while.
func postHandshakeRecords(t *testing.T, address string, handshake func(address string)) []int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var (
		finished atomic.Bool
		mu       sync.Mutex
		post     []int
		last     = time.Now()
	)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		up, err := net.Dial("tcp", address)
		if err != nil {
			return
		}
		defer func() { _ = up.Close() }()
		go eachRecord(c, up, func(typ byte, _ int) {
			if typ == 23 {
				finished.Store(true) // before the far end can have it
			}
		})
		eachRecord(up, c, func(typ byte, size int) {
			mu.Lock()
			defer mu.Unlock()
			if finished.Load() && typ == 23 {
				post = append(post, size)
			}
			last = time.Now()
		})
	}()
	handshake(ln.Addr().String())
	for {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		quiet := time.Since(last) > 500*time.Millisecond
		out := slices.Clone(post)
		mu.Unlock()
		if quiet {
			return out
		}
	}
}

// eachRecord copies src to dst, calling seen with each whole TLS record's
// type and length (header included) before the chunk that completes it
// is written on.
func eachRecord(src, dst net.Conn, seen func(typ byte, size int)) {
	var pending []byte
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		pending = append(pending, buf[:n]...)
		for len(pending) >= recordHeaderSize {
			size := recordHeaderSize + (int(pending[3])<<8 | int(pending[4]))
			if size > len(pending) {
				break
			}
			seen(pending[0], size)
			pending = pending[size:]
		}
		if _, werr := dst.Write(buf[:n]); werr != nil || err != nil {
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			_, _ = io.Copy(io.Discard, src)
			return
		}
	}
}

// A worker serves the connections handed to it in turn, so one whose
// handshake stalls after its hello authenticated must not hold up the
// next: REALITY's handshake runs on a goroutine of its own.
func TestAStalledHandshakeDoesntHoldUpTheNext(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	a := randomSpace()
	n := startShared(t, tr, theTarget(t), k, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})

	// A dialer whose hello reaches the node and nothing after it, until
	// the test ends.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		up, err := net.Dial("tcp", n.addr())
		if err != nil {
			return
		}
		defer func() { _ = up.Close() }()
		record, err := readRecord(c)
		if err != nil {
			return
		}
		_, _ = up.Write(record)
		<-stop
	}()
	stalled := transport.DialConfig{Credential: id, Settings: dialSettingsFor(t, k)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		if l, err := tr.Dial(ctx, ln.Addr().String(), stalled); err == nil {
			_ = l.Close()
		}
	}()
	select {
	case <-n.handed: // the stalled hello is the worker's
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled hello was never handed over")
	}

	start := time.Now()
	if _, err := dial(t, tr, n.addr(), k, id); err != nil {
		t.Fatalf("the next dial, %v after the stalled one: %v", time.Since(start), err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the next dial took %v", d)
	}
}
