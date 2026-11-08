package reality

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

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
	ln      transport.StreamListener
	workers map[transport.SpaceID]transport.HandoffListener

	mu       sync.Mutex
	unserved map[transport.SpaceID]bool
}

// startShared serves spaces' tables behind one reality listener whose
// target is tg; camo is the supervisor's camouflage (nil: reality's own).
// Each space's worker gets its own table; the router the merged one, or
// routerTable when given.
func startShared(t *testing.T, tr *Transport, tg *target, k keys, camo transport.Camouflage, spaces map[transport.SpaceID][]transport.PeerLink, routerTable ...transport.PeerLink) *sharedNode {
	t.Helper()
	ln, err := tr.ListenStream(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, tg, 0)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	n := &sharedNode{ln: ln, workers: map[transport.SpaceID]transport.HandoffListener{}, unserved: map[transport.SpaceID]bool{}}
	var merged []transport.PeerLink
	for space, links := range spaces {
		for i := range links {
			links[i].Peer.Space = space
		}
		merged = append(merged, links...)
		hl, err := tr.Handoff(ln.HandoffSettings(), transport.Admission{Peers: transport.NewPeerTable(links...)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hl.Close() })
		n.workers[space] = hl
	}
	if routerTable != nil {
		merged = routerTable
	}
	queues := map[transport.SpaceID]chan transport.StreamHandoff{}
	for space, hl := range n.workers {
		q := make(chan transport.StreamHandoff, 16)
		queues[space] = q
		go func() {
			for h := range q {
				hl.ServeStream(h)
			}
		}()
	}
	router := tr.StreamRouter(transport.NewPeerTable(merged...))
	serves := func(peer transport.Identity) bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.workers[peer.Space] != nil && !n.unserved[peer.Space]
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				h, ok := router.RouteStream(ln, conn, serves, camo)
				if !ok {
					return
				}
				h.Conn, h.Target = redescribe(t, h.Conn), redescribe(t, h.Target)
				queues[h.Peer.Space] <- h
			}()
		}
	}()
	return n
}

// redescribe is c as a worker gets it: a new descriptor of the
// connection, the original closed.
func redescribe(t *testing.T, c net.Conn) net.Conn {
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
	n := startShared(t, tr, theTarget(t), k, nil, map[transport.SpaceID][]transport.PeerLink{a: {plA}, b: {plB}})

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
// target, raw and whole, and reach no worker.
func TestWhatTheRouterRefusesIsSplicedWholeToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	gone, _ := shortIDs()
	a, b := randomSpace(), randomSpace()
	n := startShared(t, tr, theTarget(t), k, nil, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}, b: {peerLink(gone)}})
	n.stopServing(b)

	t.Run("wrong short id", func(t *testing.T) {
		wrong, _ := shortIDs()
		tp := newTap(t, n.addr())
		if _, err := dial(t, tr, tp.addr(), k, wrong); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("dial: %v, want %v", err, ErrNotAuthenticated)
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
		if !theTarget(t).receivedExactly(streams[0]) {
			t.Error("the replay wasn't spliced to the target raw and whole")
		}
	})
	for _, w := range n.workers {
		expectNoAccept(t, w) // past the replay's original, accepted above
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
	n := startShared(t, tr, theTarget(t), k, nil, map[transport.SpaceID][]transport.PeerLink{a: nil}, known)

	tp := newTap(t, n.addr())
	if _, err := dial(t, tr, tp.addr(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("dial: %v, want %v", err, ErrNotAuthenticated)
	}
	if !splicedWhole(theTarget(t), tp) {
		t.Error("the target didn't receive exactly what the dialer sent")
	}
	expectNoAccept(t, n.workers[a])
}

// With a camouflage of the supervisor's, what the router turns away goes
// to it with what was read, and what authenticates is still handed over
// with a target connection REALITY completes its handshake on.
func TestWithACamouflageTheRouterStillHandsOverWhatAuthenticates(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	a := randomSpace()
	camo := &recordingCamouflage{got: make(chan []byte, 4)}
	n := startShared(t, tr, theTarget(t), k, camo, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})

	if _, err := dial(t, tr, n.addr(), k, id); err != nil {
		t.Fatalf("dial: %v", err)
	}
	accept(t, n.workers[a])
	c := probe(t, n.addr(), []byte("GET / HTTP/1.1\r\n\r\n"))
	defer func() { _ = c.Close() }()
	select {
	case got := <-camo.got:
		if !bytes.HasPrefix([]byte("GET / HTTP/1.1\r\n\r\n"), got) || len(got) == 0 {
			t.Fatalf("the camouflage got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe never reached the camouflage")
	}
}

type recordingCamouflage struct{ got chan []byte }

func (recordingCamouflage) Datagram([]byte, net.Addr) {}

func (c *recordingCamouflage) Stream(conn net.Conn, consumed []byte) {
	_ = conn.Close()
	c.got <- bytes.Clone(consumed)
}

// The router's read deadline (the supervisor's bound on routing) passing
// before the hello is whole ends the routing, not the connection: it stays
// spliced to the target, which closes it when the site would.
func TestARoutingDeadlineLeavesTheConnectionToTheTarget(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	tg := newIdleTarget(t, time.Second, nil)
	ln, err := tr.ListenStream(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, tg, 0)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	router := tr.StreamRouter(transport.NewPeerTable())
	routed := make(chan time.Duration, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		start := time.Now()
		_ = conn.SetReadDeadline(start.Add(200 * time.Millisecond))
		if _, ok := router.RouteStream(ln, conn, func(transport.Identity) bool { return true }, nil); ok {
			t.Error("a partial hello was handed over")
		}
		routed <- time.Since(start)
	}()
	c := probe(t, ln.Addr().String(), []byte{recordTypeHandshake, 3, 1, 2, 0, 1})
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

// A worker's REALITY server reads what the supervisor learned of the
// target's records: Handoff puts them into this process's store, which a
// worker's sandbox couldn't fill itself; settings missing a key are
// refused.
func TestHandoffPutsTheTargetsRecordsWhereREALITYReadsThem(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	tg := theTarget(t)
	ln, err := tr.ListenStream(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, tg, 0)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var hs handoffSettings
	if err := json.Unmarshal(ln.HandoffSettings(), &hs); err != nil {
		t.Fatal(err)
	}
	if len(hs.Records) != detectedALPNs || hs.Address != ln.Addr().String() {
		t.Fatalf("handoff settings %+v", hs)
	}
	// As in a fresh worker: nothing learned, and what it gets is marked
	// so this test can tell it from what detection stored.
	for key := range hs.Records {
		xreality.GlobalPostHandshakeRecordsLens.Delete(key)
		hs.Records[key] = []int{4242}
	}
	settings, err := json.Marshal(hs)
	if err != nil {
		t.Fatal(err)
	}
	hl, err := tr.Handoff(settings, transport.Admission{Peers: transport.NewPeerTable()})
	if err != nil {
		t.Fatal(err)
	}
	_ = hl.Close()
	for key := range hs.Records {
		v, _ := xreality.GlobalPostHandshakeRecordsLens.Load(key)
		if lens, ok := v.([]int); !ok || len(lens) != 1 || lens[0] != 4242 {
			t.Errorf("%q holds %v", key, v)
		}
		xreality.GlobalPostHandshakeRecordsLens.Delete(key) // what detection learned, for the tests after
	}
	if err := detect(t.Context(), upstreamRecords{}, tg.addr(), map[string]bool{serverName: true}, detectWait); err != nil {
		t.Fatal(err)
	}
	for key := range hs.Records {
		delete(hs.Records, key)
		break
	}
	if settings, err = json.Marshal(hs); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Handoff(settings, transport.Admission{Peers: transport.NewPeerTable()}); !errors.Is(err, ErrSettings) {
		t.Fatalf("handoff settings missing a key: %v, want %v", err, ErrSettings)
	}
	for key := range hs.Records {
		if v, _ := xreality.GlobalPostHandshakeRecordsLens.Load(key); slices.Equal(asRecords(v), []int{4242}) {
			t.Errorf("refused settings stored %q", key)
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
	n := startShared(t, tr, theTarget(t), k, nil, map[transport.SpaceID][]transport.PeerLink{a: {peerLink(id)}})

	// A dialer whose hello reaches the node and nothing after it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
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
		time.Sleep(10 * time.Second)
	}()
	stalled := transport.DialConfig{Credential: id, Settings: dialSettingsFor(t, k)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		if l, err := tr.Dial(ctx, ln.Addr().String(), stalled); err == nil {
			_ = l.Close()
		}
	}()
	time.Sleep(500 * time.Millisecond) // the stalled hello handed over first

	start := time.Now()
	if _, err := dial(t, tr, n.addr(), k, id); err != nil {
		t.Fatalf("the next dial, %v after the stalled one: %v", time.Since(start), err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the next dial took %v", d)
	}
}
