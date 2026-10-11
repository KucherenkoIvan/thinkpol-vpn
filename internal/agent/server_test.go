package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// fakeSupervisor records what serverSpaces gives it, failing on demand.
type fakeSupervisor struct {
	mu                    sync.Mutex
	spaces                [][]supervisor.Space
	listeners             [][]supervisor.Listener
	failSpaces, failLists int // calls left to fail
}

func (f *fakeSupervisor) SetSpaces(sp []supervisor.Space) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spaces = append(f.spaces, sp)
	if f.failSpaces > 0 {
		f.failSpaces--
		return errors.New("no veth today")
	}
	return nil
}

func (f *fakeSupervisor) SetListeners(ls []supervisor.Listener) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listeners = append(f.listeners, ls)
	if f.failLists > 0 {
		f.failLists--
		return errors.New("address in use")
	}
	return nil
}

func (f *fakeSupervisor) last() ([]supervisor.Space, []supervisor.Listener, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var sp []supervisor.Space
	var ls []supervisor.Listener
	if n := len(f.spaces); n > 0 {
		sp = f.spaces[n-1]
	}
	if n := len(f.listeners); n > 0 {
		ls = f.listeners[n-1]
	}
	return sp, ls, len(f.spaces)
}

type runningServer struct {
	sup  *fakeSupervisor
	log  *logring.Ring
	maps chan []byte
	done chan error
	stop context.CancelFunc
}

func runServerSpaces(t *testing.T, s *testSpace, sup *fakeSupervisor) *runningServer {
	t.Helper()
	_, reg := memoryRegistry(t)
	r := &runningServer{sup: sup, log: logring.New(1 << 20), maps: make(chan []byte, 1), done: make(chan error, 1)}
	m := s.verified(t, 1)
	section, err := openSection(m, s.a)
	if err != nil {
		t.Fatal(err)
	}
	ss := &serverSpaces{
		sup: sup, reg: reg, log: slog.New(slog.NewTextHandler(r.log, nil)), keys: s.a, trust: s.trust(),
		retryAfter: testRetry, cur: m, section: section,
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.stop = cancel
	go func() { r.done <- ss.run(ctx, r.maps) }()
	t.Cleanup(func() {
		cancel()
		<-r.done
		if t.Failed() {
			t.Logf("log:\n%s", r.log)
		}
	})
	return r
}

func TestServerServesTheSpaceAndItsListeners(t *testing.T) {
	s := newTestSpace(t)
	sup := &fakeSupervisor{}
	runServerSpaces(t, s, sup)
	eventually(t, func() bool { _, ls, _ := sup.last(); return ls != nil })
	sp, ls, _ := sup.last()
	if len(sp) != 1 || sp[0].ID != s.id || len(sp[0].Inbound["memory"]) != 1 || len(ls) != 1 || ls[0].Address != s.listen.String() {
		t.Fatalf("spaces %+v, listeners %+v", sp, ls)
	}
	c, err := DecodeWorkerConfig(sp[0].Config)
	if err != nil || !c.sameNode(WorkerConfig{Keys: s.a, Trust: s.trust()}) {
		t.Fatalf("worker config %v, %v", c, err)
	}
}

// Listeners that fail at the start are retried; the node runs on.
func TestServerRetriesListenersThatFailAtTheStart(t *testing.T) {
	s := newTestSpace(t)
	sup := &fakeSupervisor{failLists: 1}
	r := runServerSpaces(t, s, sup)
	eventually(t, func() bool { return strings.Contains(r.log.String(), `msg="map applied"`) })
	if strings.Count(r.log.String(), "opening listeners failed, retrying") != 1 {
		t.Fatalf("log:\n%s", r.log)
	}
	select {
	case err := <-r.done:
		t.Fatalf("stopped: %v", err)
	default:
	}
}

func TestServerFailsWhenItCantServeItsSpace(t *testing.T) {
	s := newTestSpace(t)
	r := runServerSpaces(t, s, &fakeSupervisor{failSpaces: 1})
	select {
	case err := <-r.done:
		if err == nil || !strings.Contains(err.Error(), "no veth today") {
			t.Fatalf("got %v", err)
		}
		r.done <- err // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("it runs on without its space")
	}
}

func TestServerRetriesAFailedMap(t *testing.T) {
	s := newTestSpace(t)
	sup := &fakeSupervisor{}
	r := runServerSpaces(t, s, sup)
	eventually(t, func() bool { _, _, n := sup.last(); return n == 1 })
	sup.mu.Lock()
	sup.failSpaces = 1
	sup.mu.Unlock()
	r.maps <- s.build(t, 2)
	eventually(t, func() bool { return strings.Contains(r.log.String(), "serving the map failed, retrying") })
	eventually(t, func() bool { return strings.Contains(r.log.String(), `msg="map applied" version=2`) })
	_, _, n := sup.last()
	if n != 3 {
		t.Fatalf("%d SetSpaces calls, want the first, the failed one and the retry", n)
	}
}

func TestServerStopsTheSpaceWhileRemoved(t *testing.T) {
	s := newTestSpace(t)
	sup := &fakeSupervisor{}
	r := runServerSpaces(t, s, sup)
	eventually(t, func() bool { _, _, n := sup.last(); return n == 1 })
	r.maps <- s.buildWithout(t, 2, s.a)
	eventually(t, func() bool { _, _, n := sup.last(); return n == 2 })
	if sp, ls, _ := sup.last(); len(sp) != 0 || len(ls) != 0 {
		t.Fatalf("still serving %+v on %+v", sp, ls)
	}
	r.maps <- s.buildWithout(t, 3, s.a)
	eventually(t, func() bool { _, _, n := sup.last(); return n == 3 })
	if c := strings.Count(r.log.String(), "removed from space"); c != 1 {
		t.Fatalf("%d removal messages", c)
	}
	r.maps <- s.build(t, 4)
	eventually(t, func() bool { return strings.Contains(r.log.String(), "back in space") })
	eventually(t, func() bool { sp, _, _ := sup.last(); return len(sp) == 1 })
}

// fakeSession is a worker's view of its supervisor, for ServeSpace.
type fakeSession struct {
	worker.Session
	config    chan []byte
	listeners chan []worker.SharedListener
}

func newFakeSession(space netmap.SpaceID) *fakeSession {
	f := &fakeSession{config: make(chan []byte, 1), listeners: make(chan []worker.SharedListener, 1)}
	f.Session = worker.Session{Space: space, Config: f.config, Listeners: f.listeners, SharedCounters: make(chan ipc.SharedCounters)}
	return f
}

func (s *testSpace) workerConfig(t *testing.T, keys NodeKeys, version uint64) []byte {
	t.Helper()
	b, err := WorkerConfig{Keys: keys, Trust: s.trust(), Map: s.build(t, version)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServeSpace(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	serve := func(t *testing.T, sess *fakeSession) (*runningNode, func() error) {
		n := newRunningNode()
		base := n.dataPlane(reg, NodeKeys{}, nil)
		done := make(chan error, 1)
		go func() {
			done <- serveSpace(slog.New(slog.NewTextHandler(n.log, &slog.HandlerOptions{Level: slog.LevelDebug})), base)(n.ctx, sess.Session)
		}()
		return n, func() error {
			select {
			case err := <-done:
				return err
			case <-time.After(10 * time.Second):
				n.stop()
				t.Fatalf("still serving:\n%s", n.log)
				return nil
			}
		}
	}

	t.Run("later configs reach the data plane", func(t *testing.T) {
		sess := newFakeSession(s.id)
		sess.config <- s.workerConfig(t, s.a, 1)
		n, wait := serve(t, sess)
		n.waitLog(t, `msg="map applied" version=1`)
		sess.config <- s.workerConfig(t, s.a, 2)
		n.waitLog(t, `msg="map applied" version=2`)
		n.stop()
		if err := wait(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another space's config", func(t *testing.T) {
		sess := newFakeSession(netmap.SpaceID{1})
		sess.config <- s.workerConfig(t, s.a, 1)
		_, wait := serve(t, sess)
		if err := wait(); err == nil || !strings.Contains(err.Error(), "sent to the worker of space") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("other keys later", func(t *testing.T) {
		sess := newFakeSession(s.id)
		sess.config <- s.workerConfig(t, s.a, 1)
		n, wait := serve(t, sess)
		n.waitLog(t, `msg="map applied" version=1`)
		sess.config <- s.workerConfig(t, s.b, 2)
		if err := wait(); err == nil || !strings.Contains(err.Error(), "changed the worker's keys or trust") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestSharedInbound(t *testing.T) {
	_, reg := memoryRegistry(t)
	updates := make(chan []worker.SharedListener, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := SharedInbound(ctx, reg, updates)
	if got := in.Listeners(netmap.Section{}); len(got) != 0 {
		t.Fatalf("listeners before any set: %+v", got)
	}
	gone := make(chan struct{})
	close(gone)
	updates <- []worker.SharedListener{{ID: 1, Transport: "memory", Done: gone}, {ID: 2, Transport: "memory", Done: make(chan struct{})}}
	select {
	case <-in.Changed():
	case <-time.After(5 * time.Second):
		t.Fatal("a new set didn't signal Changed")
	}
	got := in.Listeners(netmap.Section{})
	if len(got) != 2 || got[0].Key == got[1].Key {
		t.Fatalf("listeners %+v", got)
	}

	// A listener whose Done is closed is never opened.
	opened := map[string]int{}
	want := []Listener{}
	for _, l := range got {
		want = append(want, Listener{Key: l.Key, Transport: l.Transport, Done: l.Done,
			Open: func(context.Context, transport.Peers) (transport.Listener, error) {
				opened[l.Key]++
				return nil, errors.New("not in this test")
			}})
	}
	ls := &listenerSet{
		peers: func(string) transport.Peers { return transport.NewPeerTable() },
		log:   slog.New(slog.DiscardHandler), retryAfter: time.Hour,
		ended: make(chan struct{}, 1), serving: map[string]*served{}, retryAt: map[string]time.Time{},
	}
	ls.reconcile(context.Background(), want)
	ls.reconcile(context.Background(), want) // the failed one waits for its retry
	if opened[got[0].Key] != 0 || opened[got[1].Key] != 1 {
		t.Fatalf("opened %v", opened)
	}
}

func TestOnlyTheOwnersWorkerOutputIsCopied(t *testing.T) {
	var buf bytes.Buffer
	own, guest := netmap.SpaceID{1}, netmap.SpaceID{2}
	output := ownerOutput(own, &workerOutput{w: &buf})
	if output(guest) != nil {
		t.Fatal("a guest space's worker output is copied into the node's log")
	}
	w := output(own)
	_, _ = w.Write([]byte("evil \x1b[2J\x07 tab\there \x7f c1 \u009b bidi \u202e\u2066 bad \xff\xc3 ok é\n"))
	want := "worker space=" + own.String() + ` evil \x1b[2J\x07 tab` + "\there " + `\x7f c1 \u009b bidi \u202e\u2066 bad \xff\xc3 ok ` + "é\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
