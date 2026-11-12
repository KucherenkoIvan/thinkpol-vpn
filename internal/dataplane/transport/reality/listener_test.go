package reality

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
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

// A target that closes its side before it sent anything, as nginx does
// on bytes that aren't TLS (a lingering close: its FIN, then it reads on),
// is passed on as the site's own close would be: the client gets the FIN,
// and what it still sends goes on to the target rather than being reset,
// so a prober sees the site's close, not a reset.
func TestATargetsSilentCloseReachesTheClientAsItsFIN(t *testing.T) {
	setLinger(t, 2*time.Second)
	header := []byte{23, 3, 3, 0, 16} // application data first: no hello
	after := make(chan []byte, 1)
	tg := newIdleTarget(t, 5*time.Second, func(c *net.TCPConn, r io.Reader) {
		if !bytes.HasPrefix(r.(*recorder).bytes(), header) {
			_, _ = io.Copy(io.Discard, r) // Listen's own checks of the target
			return
		}
		_ = c.CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		rest, _ := io.ReadAll(r)
		after <- rest
	})
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	c := probe(t, l.Addr().String(), header)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("the client read %d bytes, %v; want the target's FIN", n, err)
	}
	more := bytes.Repeat([]byte{0x42}, 995)
	if _, err := c.Write(more); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	select {
	case rest := <-after:
		if !bytes.HasSuffix(rest, more) {
			t.Errorf("the target read %d bytes after its FIN, want the client's %d", len(rest), len(more))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the target never finished reading")
	}
}

// setLinger sets spliceLinger for one test.
func setLinger(t *testing.T, d time.Duration) {
	linger := spliceLinger
	spliceLinger = d
	t.Cleanup(func() { spliceLinger = linger })
}

// setWriteTimeout sets spliceWriteTimeout for one test.
func setWriteTimeout(t *testing.T, d time.Duration) {
	was := spliceWriteTimeout
	spliceWriteTimeout = d
	t.Cleanup(func() { spliceWriteTimeout = was })
}

// setHelloTimeout sets helloTimeout for one test.
func setHelloTimeout(t *testing.T, d time.Duration) {
	was := helloTimeout
	helloTimeout = d
	t.Cleanup(func() { helloTimeout = was })
}

// setGateBounds sets the listeners' bounds for one test.
func setGateBounds(t *testing.T, mirrors, splices int) {
	was := gateBounds
	gateBounds.mirrors, gateBounds.splices = mirrors, splices
	t.Cleanup(func() { gateBounds = was })
}

// afterTheFIN is a prober comparing a server with its site: it sends what
// to address, reads until the far end ends the connection, then writes
// every 200 ms, and says how the connection ended and which write after
// the FIN failed first.
func afterTheFIN(t *testing.T, address string, what []byte) string {
	t.Helper()
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(what); err != nil {
		return fmt.Sprintf("the probe's write failed: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	switch _, err := io.Copy(io.Discard, c); {
	case isTimeout(err):
		return "still open"
	case err != nil:
		return "reset before any FIN"
	}
	for i := range 4 {
		time.Sleep(200 * time.Millisecond)
		if _, err := c.Write([]byte("after the FIN")); err != nil {
			return fmt.Sprintf("FIN, then write %d failed", i+1)
		}
	}
	return "FIN, then 4 writes went through"
}

// probesAfterTheFIN are random probes of 1000 bytes, as the lab's prober
// sends, starting as a TLS record, an SSLv2 hello and plain text would.
func probesAfterTheFIN() map[string][]byte {
	r := mathrand.New(mathrand.NewPCG(1, 2))
	out := map[string][]byte{}
	for name, first := range map[string]byte{"tls record": recordTypeHandshake, "sslv2": 0x8f, "text": 'Q'} {
		b := make([]byte, 1000)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		b[0] = first
		out[name] = b
	}
	return out
}

// A site that closes whole once it read a probe that isn't TLS resets a
// prober writing after its FIN; through the listener the same write
// fails. The site here is a model: it reads all it is sent, then closes.
func TestAfterTheSitesFINTheSameWriteFails(t *testing.T) {
	tg := newIdleTarget(t, time.Minute, func(c *net.TCPConn, r io.Reader) {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = io.Copy(io.Discard, r)
	})
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	for name, what := range probesAfterTheFIN() {
		t.Run(name, func(t *testing.T) {
			site := afterTheFIN(t, tg.addr(), what)
			if site != "FIN, then write 2 failed" {
				t.Fatalf("the model site: %s", site)
			}
			if got := afterTheFIN(t, l.Addr().String(), what); got != site {
				t.Errorf("through the listener: %s; the site: %s", got, site)
			}
		})
	}
}

// A stranger that stops reading, its splice's writes stalled on its full
// window, is cut once a write waited spliceWriteTimeout, freeing its
// splice slot for the next stranger, whom the bound would close.
func TestAClientThatNeverReadsFreesItsSpliceSlot(t *testing.T) {
	setWriteTimeout(t, 300*time.Millisecond)
	setGateBounds(t, maxMirrors, 1)
	tg := newIdleTarget(t, time.Minute, func(c *net.TCPConn, _ io.Reader) {
		_ = c.SetDeadline(time.Time{})
		chunk := make([]byte, 64<<10)
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	})
	n := startShared(t, newTransport(Options{}), tg, newKeys(t), nil)
	get := []byte("GET / HTTP/1.1\r\n\r\n")
	stalled := probe(t, n.addr(), get)
	_ = stalled.(*net.TCPConn).SetReadBuffer(4 << 10)
	if v := n.verdict(t); v != transport.StreamUnknown {
		t.Fatalf("the stalled stranger's verdict %d", v)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c := probe(t, n.addr(), get)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if k, _ := c.Read(make([]byte, 1)); k == 1 {
			return // spliced: the target's bytes
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("a client that never reads still holds the only splice slot")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// An idle stranger holds a slot among the connections being decided for
// helloTimeout at most, then stays spliced to the target, which ends it
// as the site would: it can't keep members' hellos from being decided
// until the target gives up on it.
func TestAnIdleStrangerFreesItsMirrorSlotAtTheHelloTimeout(t *testing.T) {
	setHelloTimeout(t, 300*time.Millisecond)
	setGateBounds(t, 1, maxSplices)
	tr := newTransport(Options{})
	k := newKeys(t)
	id, verifier := shortIDs()
	tg := newIdleTarget(t, time.Minute, nil)
	l := listenTo(t, tr, tg, k, peerLink(verifier))
	idle := probe(t, l.Addr().String(), nil)
	if tg.connWith(nil) == nil {
		t.Fatal("the idle stranger's target was never dialled")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := dial(t, tr, l.Addr().String(), k, id); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("an idle stranger still holds the only slot for hellos being decided")
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = idle.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := idle.Read(make([]byte, 1)); !isTimeout(err) {
		t.Errorf("the idle stranger was closed (%v), not left to the target", err)
	}
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

// Before the hello is decided, a target that closes whole without a word
// (no lingering close) resets a prober writing after its FIN at the write
// the site's own reset would: the first write goes on to the target,
// whose reset resets the client at once, so the second fails.
func TestBeforeTheHelloATargetsWholeCloseResetsTheClient(t *testing.T) {
	tg := newIdleTarget(t, 300*time.Millisecond, nil)
	l := listenTo(t, newTransport(Options{}), tg, newKeys(t))
	c := probe(t, l.Addr().String(), []byte{recordTypeHandshake, 3, 1, 0x02})
	closedWithin(t, c, 5*time.Second)
	for i := range 2 {
		_, err := c.Write([]byte("after the FIN"))
		if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
			return
		}
		if err != nil {
			t.Fatalf("write %d past the FIN: %v, want %v or %v", i, err, syscall.ECONNRESET, syscall.EPIPE)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("two writes past the FIN went through: the site's reset reached the client late or not at all")
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
	ln := listenUnlearned(t)
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

// listenUnlearned listens on loopback until it gets an address REALITY
// never detected records for in this process, keeping the others open
// until the test ends. What REALITY learned outlives the target it learned
// it from, and -count reruns the tests in one process, where a loopback
// port an earlier target used comes round again: detect would take that
// target's records for the new one's and return at once.
func listenUnlearned(t *testing.T) net.Listener {
	t.Helper()
	for range 100 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if unlearned(ln.Addr().String()) {
			return ln
		}
		t.Cleanup(func() { _ = ln.Close() })
	}
	t.Fatal("100 loopback addresses in a row whose records REALITY already detected")
	return nil
}

// unlearned reports whether nothing about dest is known to detect: no
// records under any of its keys in REALITY's store, no detection of ours.
func unlearned(dest string) bool {
	for alpn := range detectedALPNs {
		if _, ok := (upstreamRecords{}).load(recordsKey(dest, serverName, alpn)); ok {
			return false
		}
	}
	detections.mu.Lock()
	defer detections.mu.Unlock()
	_, ok := detections.byDest[dest]
	return !ok
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
	ahead := startedLongAgo(newTransport(Options{Now: func() time.Time { return time.Now().Add(2 * time.Minute) }}))
	l := listenFor(t, ahead, k, 60, peerLink(id))
	if _, err := dial(t, newTransport(Options{}), l.Addr().String(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("dial sealed now through a 1-minute window 2 minutes ahead: %v, want %v", err, ErrNotAuthenticated)
	}
	ok := startedLongAgo(newTransport(Options{Now: func() time.Time { return time.Now().Add(30 * time.Second) }}))
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
