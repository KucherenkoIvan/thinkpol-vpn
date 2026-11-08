package reality

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	xreality "github.com/xtls/reality"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

// listenTo starts a listener accepting peers whose target is tg.
func listenTo(t *testing.T, tr *Transport, tg *target, k keys, peers ...transport.PeerLink) transport.Listener {
	t.Helper()
	l, err := tr.Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, k, tg, 0)},
		transport.Admission{Peers: transport.NewPeerTable(peers...)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// probe connects to address and sends what.
func probe(t *testing.T, address string, what []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write(what); err != nil {
		t.Fatal(err)
	}
	return c
}

// closedWithin reports how long c took to be closed by its far end, or
// fails once within passed: a prober reads until its connection ends.
func closedWithin(t *testing.T, c net.Conn, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	_ = c.SetReadDeadline(start.Add(within))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("still open after %v", within)
	}
	return time.Since(start)
}

// A prober that stalls, sending nothing or part of a record, is closed when
// the target closes it, as the site itself would close it, not on a timer
// of the listener's: the target is dialled at accept and sees each byte as
// it arrives.
func TestAStallingProbeIsClosedWhenTheTargetClosesIt(t *testing.T) {
	const idle = 500 * time.Millisecond
	tg := newIdleTarget(t, idle, nil)
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	partial := append([]byte{recordTypeHandshake, 3, 1, 0x02, 0x05}, make([]byte, 300)...) // 517 bytes announced, 300 sent
	for _, tc := range []struct {
		name string
		sent []byte
	}{
		{"nothing", nil},
		{"a partial record", partial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := probe(t, l.Addr().String(), tc.sent)
			took := closedWithin(t, c, helloTimeout/2)
			if took < idle/2 {
				t.Errorf("closed after %v, before the target's %v", took, idle)
			}
			if !tg.receivedExactly(tc.sent) {
				t.Error("the target didn't receive exactly what the prober sent")
			}
		})
	}
}

// setLinger sets spliceLinger for one test.
func setLinger(t *testing.T, d time.Duration) {
	linger := spliceLinger
	spliceLinger = d
	t.Cleanup(func() { spliceLinger = linger })
}

// badRequest is a target answering a connection whose handshake failed
// with a line and its FIN, reading on until the far end closes.
func badRequest(c *net.TCPConn, r io.Reader) {
	_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	_ = c.CloseWrite()
	_ = c.SetDeadline(time.Time{})
	_, _ = io.Copy(io.Discard, r)
}

// Once the target answered and closed its side, a splice gives a client
// that stays silent spliceLinger, then closes both connections.
func TestASpliceEndsOnceTheTargetClosedAndTheClientStaysSilent(t *testing.T) {
	setLinger(t, 200*time.Millisecond)
	tg := newIdleTarget(t, time.Minute, badRequest)
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))

	sent := []byte("GET / HTTP/1.1\r\n\r\n")
	c := probe(t, l.Addr().String(), sent)
	closedWithin(t, c, 5*time.Second) // the target's FIN; c stays open and silent
	conn := tg.connWith(sent)
	if conn == nil {
		t.Fatal("the probe wasn't spliced to the target")
	}
	select {
	case <-conn.done:
	case <-time.After(3 * time.Second):
		t.Fatal("the splice still holds the target's connection")
	}
}

// After the client's FIN the target's answer flows on for as long as it
// keeps coming, past spliceLinger: the linger is an idle timeout.
func TestAnAnswerAfterTheClientsFINFlowsOnPastTheLinger(t *testing.T) {
	const linger, gap, chunks = 500 * time.Millisecond, 200 * time.Millisecond, 5
	setLinger(t, linger)
	tg := newIdleTarget(t, time.Minute, func(c *net.TCPConn, r io.Reader) {
		_, _ = io.Copy(io.Discard, r) // until the client's FIN
		for i := range chunks {
			if i > 0 {
				time.Sleep(gap)
			}
			if _, err := c.Write([]byte("chunk\n")); err != nil {
				return
			}
		}
	})
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	c := probe(t, l.Addr().String(), []byte("GET /large HTTP/1.1\r\n\r\n"))
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if want := bytes.Repeat([]byte("chunk\n"), chunks); !bytes.Equal(got, want) {
		t.Errorf("the client got %q, want %q", got, want)
	}
}

// Before the hello is decided, the target closing without a word closes
// the client whole, as REALITY's server does: a prober writing after the
// FIN is reset.
func TestBeforeTheHelloTheTargetsCloseClosesTheClientWhole(t *testing.T) {
	tg := newIdleTarget(t, 300*time.Millisecond, nil)
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	c := probe(t, l.Addr().String(), []byte{recordTypeHandshake, 3, 1, 0x02})
	closedWithin(t, c, 5*time.Second)
	if _, err := c.Write([]byte("after the FIN")); err != nil {
		return // reset already
	}
	time.Sleep(100 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("read after writing past the FIN: %v, want %v", err, syscall.ECONNRESET)
	}
}

// Before the hello is decided, the client's FIN closes the target whole,
// as REALITY's server does: what the target sends after it doesn't reach
// the client.
func TestBeforeTheHelloTheClientsFINClosesTheTargetWhole(t *testing.T) {
	tg := newIdleTarget(t, time.Minute, func(c *net.TCPConn, r io.Reader) {
		_, _ = io.Copy(io.Discard, r) // until the client's FIN
		_, _ = c.Write([]byte("after the client's FIN"))
	})
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	partial := append([]byte{recordTypeHandshake, 3, 1, 0x02, 0x05}, make([]byte, 300)...)
	c := probe(t, l.Addr().String(), partial)
	if !tg.receivedExactly(partial) {
		t.Fatal("the target didn't receive the partial hello")
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 0 {
		t.Errorf("the client got %q after its FIN", got)
	}
}

// Closing the listener ends its live splices.
func TestClosingTheListenerEndsItsSplices(t *testing.T) {
	tg := newIdleTarget(t, time.Minute, nil)
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	sent := []byte("GET / HTTP/1.1\r\n\r\n")
	c := probe(t, l.Addr().String(), sent)
	if !tg.receivedExactly(sent) {
		t.Fatal("the probe wasn't spliced to the target")
	}
	_ = l.Close()
	closedWithin(t, c, 3*time.Second)
}

// closedPort is a loopback address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// recordsKey is the key REALITY's own detection stores a target's records
// under, at the pinned module.
func TestRecordsKeyIsREALITYs(t *testing.T) {
	dest := closedPort(t)
	const name = "keys.example.net"
	xreality.DetectPostHandshakeRecordsLens(&xreality.Config{Type: "tcp", Dest: dest, ServerNames: map[string]bool{name: true}})
	for alpn := range detectedALPNs {
		if _, ok := xreality.GlobalPostHandshakeRecordsLens.Load(recordsKey(dest, name, alpn)); !ok {
			t.Errorf("REALITY stored nothing under %q", recordsKey(dest, name, alpn))
		}
	}
}

// Listen fails when REALITY can't learn the target's records: a target
// that can't be reached, or one that never answers a handshake.
func TestListenFailsUnlessTheTargetsRecordsAreLearned(t *testing.T) {
	names := map[string]bool{serverName: true}
	t.Run("unreachable", func(t *testing.T) {
		settings := mustMarshal(t, &transportv1.RealityListenSettings{
			PrivateKey: newKeys(t).private, Target: closedPort(t), ServerNames: []string{serverName},
		})
		_, err := newTransport(Options{}).Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}, transport.Admission{Peers: transport.NewPeerTable()})
		if err == nil {
			t.Fatal("listening with an unreachable target")
		}
	})
	t.Run("stalled", func(t *testing.T) {
		f := newFront(t)
		if err := detect(t.Context(), upstreamRecords{}, f.addr(), names, 300*time.Millisecond); err == nil {
			t.Fatal("detected the records of a target that never answers")
		}
	})
	t.Run("a site", func(t *testing.T) {
		if err := detect(t.Context(), upstreamRecords{}, theTarget(t).addr(), names, detectWait); err != nil {
			t.Fatal(err)
		}
	})
}

// Listen fails on a target whose certificate its roots don't verify,
// naming the target: REALITY would imitate it without its post-handshake
// records.
func TestListenFailsOnATargetCertificateTheRootsDontVerify(t *testing.T) {
	tg := theTarget(t)
	settings := listenSettingsFor(t, newKeys(t), tg, 0)
	cfg := transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}
	_, err := New(Options{}).Listen(t.Context(), cfg, transport.Admission{Peers: transport.NewPeerTable()})
	if err == nil || !strings.Contains(err.Error(), tg.addr()) {
		t.Fatalf("listen with a self-signed target and the system roots: %v, want an error naming %s", err, tg.addr())
	}
	l, err := newTransport(Options{}).Listen(t.Context(), cfg, transport.Admission{Peers: transport.NewPeerTable()})
	if err != nil {
		t.Fatalf("listen trusting the target's certificate: %v", err)
	}
	_ = l.Close()
}

// Listen fails on a target that doesn't speak TLS 1.3, saying so: REALITY
// imitates only a TLS 1.3 ServerHello, and every authenticated handshake
// would fail.
func TestListenFailsOnATargetWithoutTLS13(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{targetCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	settings := mustMarshal(t, &transportv1.RealityListenSettings{
		PrivateKey: newKeys(t).private, Target: ln.Addr().String(), ServerNames: []string{serverName},
	})
	l, err := newTransport(Options{}).Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}, transport.Admission{Peers: transport.NewPeerTable()})
	if err == nil {
		_ = l.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "doesn't speak TLS 1.3") {
		t.Fatalf("listen with a TLS 1.2-only target: %v, want an error saying it doesn't speak TLS 1.3", err)
	}
}

// The target's certificate check dials through the Control hook, as every
// other connection of the listener does.
func TestTheTargetsCertificateCheckDialsThroughControl(t *testing.T) {
	tg := theTarget(t)
	var mu sync.Mutex
	var dialled []string
	errRefused := errors.New("refused by control")
	control := func(_, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		dialled = append(dialled, address)
		return errRefused
	}
	err := verifyTarget(t.Context(), tg.addr(), map[string]bool{serverName: true}, targetRoots, detectWait, control)
	if !errors.Is(err, errRefused) {
		t.Errorf("certificate check with a control refusing every dial: %v, want %v", err, errRefused)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(dialled, tg.addr()) {
		t.Errorf("control saw %v, want the target %s", dialled, tg.addr())
	}
}

// fakeRecords is REALITY's detection store with detections the test
// drives: each key newly detected is stored pending (false) and handed to
// started.
type fakeRecords struct {
	mu      sync.Mutex
	m       map[string]any
	started func(key string)
}

func (f *fakeRecords) detect(cfg *xreality.Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name := range cfg.ServerNames {
		for alpn := range detectedALPNs {
			key := recordsKey(cfg.Dest, name, alpn)
			if _, ok := f.m[key]; !ok {
				f.m[key] = false
				if f.started != nil {
					go f.started(key)
				}
			}
		}
	}
}

func (f *fakeRecords) load(key string) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	return v, ok
}

func (f *fakeRecords) delete(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
}

func (f *fakeRecords) store(key string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = v
}

// finish is REALITY's detection ending as upstream's does once it read
// the target's records: they are stored, and only later, its connection
// closed, does it check the key and store an empty result over a pending
// one.
func (f *fakeRecords) finish(key string, records []int, last time.Duration) {
	f.store(key, records)
	time.Sleep(last)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, pending := f.m[key].(bool); pending {
		f.m[key] = []int{}
	}
}

func asRecords(v any) []int {
	r, _ := v.([]int)
	return r
}

// A detection given up on that stored its records hasn't made its last
// write yet: detect waits before forgetting them, so that write can't land
// on a fresh detection's pending key and end it with an empty result.
func TestADetectionGivenUpOnIsForgottenOnlyOnceItsLastWriteIsDone(t *testing.T) {
	dest := "fake-target:" + t.Name()
	names := map[string]bool{serverName: true}
	f := &fakeRecords{m: map[string]any{}}
	if err := detect(t.Context(), f, dest, names, 100*time.Millisecond); err == nil {
		t.Fatal("detected the records of a detection that never ends")
	}

	fresh := []int{42}
	f.mu.Lock()
	f.started = func(key string) {
		time.Sleep(500 * time.Millisecond)
		f.finish(key, fresh, 0)
	}
	var orphans []string
	for key := range f.m {
		orphans = append(orphans, key)
	}
	f.mu.Unlock()
	for _, key := range orphans {
		go f.finish(key, []int{7}, 200*time.Millisecond)
	}
	if err := detect(t.Context(), f, dest, names, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, key := range orphans {
		if v, _ := f.load(key); !slices.Equal(asRecords(v), fresh) {
			t.Errorf("%q holds %v once detect ended, want the fresh detection's %v", key, v, fresh)
		}
	}
}

// front is a TCP front for theTarget that holds every connection, silent,
// until answer; from then on new connections are passed through to
// theTarget, and release closes the held ones.
type front struct {
	t  *testing.T
	ln net.Listener

	mu        sync.Mutex
	answering bool
	held      []net.Conn
	accepted  int
}

func newFront(t *testing.T) *front {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &front{t: t, ln: ln}
	t.Cleanup(func() { _ = ln.Close(); f.release() })
	tg := theTarget(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.accepted++
			answering := f.answering
			if !answering {
				f.held = append(f.held, c)
			}
			f.mu.Unlock()
			if answering {
				go passThrough(c, tg.addr())
			}
		}
	}()
	return f
}

func passThrough(c net.Conn, address string) {
	defer func() { _ = c.Close() }()
	up, err := net.Dial("tcp", address)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
	_, _ = io.Copy(c, up)
}

func (f *front) addr() string { return f.ln.Addr().String() }

func (f *front) answer() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answering = true
}

func (f *front) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.held {
		_ = c.Close()
	}
	f.held = nil
}

func (f *front) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted
}

// REALITY's detection runs on after detect gave up on it: a later detect
// fails while that one runs, then forgets every result it left and
// detects again, so a detection given up on never stands in for a fresh
// one.
func TestADetectionGivenUpOnIsAwaitedThenDoneAgain(t *testing.T) {
	names := map[string]bool{serverName: true, "other.example.net": true}
	f := newFront(t)
	if err := detect(t.Context(), upstreamRecords{}, f.addr(), names, 300*time.Millisecond); err == nil {
		t.Fatal("detected the records of a target that never answers")
	}

	f.answer()
	if err := detect(t.Context(), upstreamRecords{}, f.addr(), names, 300*time.Millisecond); err == nil {
		t.Fatal("detected again while the detection given up on still runs")
	}

	f.release()
	deadline := time.Now().Add(5 * time.Second)
	for name := range names {
		for alpn := range detectedALPNs {
			for {
				v, _ := xreality.GlobalPostHandshakeRecordsLens.Load(recordsKey(f.addr(), name, alpn))
				if _, done := v.([]int); done {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the detection given up on didn't end once its connections closed")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	before := f.connections()
	if err := detect(t.Context(), upstreamRecords{}, f.addr(), names, detectWait); err != nil {
		t.Fatal(err)
	}
	// REALITY's detection dials twice per server name and ALPN.
	if want := 2 * len(names) * detectedALPNs; f.connections()-before < want {
		t.Errorf("detected again with %d connections, want %d", f.connections()-before, want)
	}
}

// A refused entry sharing a short id with a valid one drops the short id:
// neither is taken, and both are reported.
func TestARefusedEntryDropsItsShortID(t *testing.T) {
	tr := newTransport(Options{})
	k := newKeys(t)
	id, _ := shortIDs()
	valid := peerLink(id)
	refused := peerLink(id)
	refused.Shaping = transport.Shaping{BatchWindow: time.Millisecond}
	l := listenFor(t, tr, k, 0, valid, refused)

	if _, err := dial(t, tr, l.Addr().String(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("dial with a short id a refused entry has too: %v, want %v", err, ErrNotAuthenticated)
	}
	var reported []transport.Identity
	for _, pe := range l.(interface{ Rejected() []transport.PeerError }).Rejected() {
		reported = append(reported, pe.Peer)
	}
	if !slices.Contains(reported, valid.Peer) || !slices.Contains(reported, refused.Peer) {
		t.Errorf("rejected %v, want both peers", reported)
	}
}

// The listener's own freshness check runs on its clock (Options.Now)
// before REALITY's, which runs on the real clock: a hello sealed outside
// the listener's window is refused even where REALITY would take it.
func TestTheListenersClockRefusesAStaleSealBeforeREALITY(t *testing.T) {
	k := newKeys(t)
	id, _ := shortIDs()
	ahead := newTransport(Options{Now: func() time.Time { return time.Now().Add(2 * time.Minute) }})
	l := listenFor(t, ahead, k, 60, peerLink(id))
	if _, err := dial(t, newTransport(Options{}), l.Addr().String(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("dial sealed now through a 1-minute window 2 minutes ahead: %v, want %v", err, ErrNotAuthenticated)
	}
	ok := newTransport(Options{Now: func() time.Time { return time.Now().Add(30 * time.Second) }})
	l = listenFor(t, ok, k, 60, peerLink(id))
	if _, err := dial(t, newTransport(Options{}), l.Addr().String(), k, id); err != nil {
		t.Errorf("dial sealed now through a 1-minute window 30 s ahead: %v", err)
	}
}

// slowClock is a listener clock that takes d to read: a node loaded enough
// that authenticating a hello takes longer than the target takes to answer
// it.
func slowClock(d time.Duration) func() time.Time {
	return func() time.Time {
		time.Sleep(d)
		return time.Now()
	}
}

// A target that answers the hello before the listener decided can't reach
// an authenticated client: the hello's tail reaches the target only from
// REALITY, under its lock, so REALITY has taken the connection before the
// target can answer.
func TestATargetAnsweringBeforeTheListenerDecidedDoesntReachAnAuthenticatedClient(t *testing.T) {
	tg := newIdleTarget(t, time.Minute, nil)
	k := newKeys(t)
	id, _ := shortIDs()
	l := listenTo(t, newTransport(Options{Now: slowClock(20 * time.Millisecond)}), tg, k, peerLink(id))
	for i := range 20 {
		if _, err := dial(t, newTransport(Options{}), l.Addr().String(), k, id); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_, _, err := l.Accept(ctx)
		cancel()
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
	}
}

// On an authenticated connection the target sees the client's hello once,
// byte for byte, as from REALITY's own listener.
func TestTheTargetSeesAnAuthenticatedHelloOnce(t *testing.T) {
	tg := newIdleTarget(t, time.Minute, nil)
	k := newKeys(t)
	id, _ := shortIDs()
	l := listenTo(t, newTransport(Options{}), tg, k, peerLink(id))
	tp := newTap(t, l.Addr().String())
	if _, err := dial(t, newTransport(Options{}), tp.addr(), k, id); err != nil {
		t.Fatal(err)
	}
	streams := tp.captured()
	if len(streams) != 1 || len(streams[0]) < recordHeaderSize {
		t.Fatalf("captured %d streams, want 1 starting with a record", len(streams))
	}
	s := streams[0]
	hello := s[:recordHeaderSize+(int(s[3])<<8|int(s[4]))]
	if !tg.receivedExactly(hello) {
		t.Errorf("the target received %d streams, none exactly the %d-byte hello", len(tg.received()), len(hello))
	}
}
