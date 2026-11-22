package reality

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

// The map gives a dual-stack server a listener per family on one port,
// 0.0.0.0:p and [::]:p (devmap's listenersFor). Both must bind, each
// accepting its own family: on plain "tcp" the first would take both
// families and the second fail for good, retried by the agent.
func TestListenWildcardsOfBothFamiliesOnOnePort(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	tg := theTarget(t)
	tr := newTransport(Options{})
	settings := listenSettingsFor(t, newKeys(t), tg, 0)
	v4, _, err := tr.openListener(t.Context(), transport.ListenConfig{Address: "0.0.0.0:0", Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = v4.Close() }()
	port := netip.MustParseAddrPort(v4.Addr().String()).Port()
	v6, _, err := tr.openListener(t.Context(), transport.ListenConfig{Address: netip.AddrPortFrom(netip.IPv6Unspecified(), port).String(), Settings: settings})
	if err != nil {
		t.Fatalf("[::]:%d next to 0.0.0.0:%d: %v", port, port, err)
	}
	defer func() { _ = v6.Close() }()
	for _, c := range []struct {
		ln   net.Listener
		dial netip.Addr
	}{
		{v4, netip.MustParseAddr("127.0.0.1")},
		{v6, netip.IPv6Loopback()},
	} {
		to := netip.AddrPortFrom(c.dial, port).String()
		conn, err := net.DialTimeout("tcp", to, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", to, err)
		}
		_ = c.ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
		got, err := c.ln.Accept()
		if err != nil {
			t.Fatalf("%s didn't accept the dial to %s: %v", c.ln.Addr(), to, err)
		}
		if from := netip.MustParseAddrPort(got.RemoteAddr().String()).Addr().Unmap(); from != c.dial {
			t.Errorf("%s accepted a connection from %s, want %s", c.ln.Addr(), from, c.dial)
		}
		_ = got.Close()
		_ = conn.Close()
	}
}

// A listener that can't bind never dials its target: the agent retries
// a failed listener every few seconds, and each retry would otherwise be
// a TLS handshake with the target from the server's address.
func TestAListenerThatCantBindDoesntDialTheTarget(t *testing.T) {
	tg := newIdleTarget(t, time.Second, nil)
	taken, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	tr := newTransport(Options{})
	cfg := transport.ListenConfig{Address: taken.Addr().String(), Settings: listenSettingsFor(t, newKeys(t), tg, 0)}
	for range 3 {
		l, err := tr.Listen(t.Context(), cfg, transport.Admission{Peers: transport.NewPeerTable()})
		if err == nil {
			_ = l.Close()
			t.Fatalf("listened on %s, which is taken", cfg.Address)
		}
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("listen on a taken address: %v, want it in use", err)
		}
	}
	if n := len(tg.received()); n != 0 {
		t.Fatalf("the target got %d connections from listeners that couldn't bind, want none", n)
	}
}

// A target whose check failed isn't checked again before its wait ends,
// however often the listener is retried, and the waits grow: a failing
// target never becomes a dial on the agent's fixed retry period.
func TestAFailedTargetCheckBacksOff(t *testing.T) {
	var dials atomic.Int32
	site, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = site.Close() })
	go func() {
		for {
			c, err := site.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			_ = c.Close() // no TLS: the check fails
		}
	}()
	tr := newTransport(Options{})
	now := time.Now()
	tr.checks.now = func() time.Time { return now }
	settings := mustMarshal(t, &transportv1.RealityListenSettings{
		PrivateKey: newKeys(t).private, Target: site.Addr().String(), ServerNames: []string{serverName},
	})
	listen := func() {
		t.Helper()
		l, err := tr.Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}, transport.Admission{Peers: transport.NewPeerTable()})
		if err == nil {
			_ = l.Close()
			t.Fatal("listened with a target that doesn't speak TLS")
		}
	}
	dialsWithin := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for dials.Load() < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		if got := dials.Load(); got != want {
			t.Fatalf("the target was dialled %d times, want %d", got, want)
		}
	}
	listen()
	dialsWithin(1)
	// After the nth failure in a row the wait is within [d/2, d], d
	// doubling from checkBackoffMin: retried just short of d/2, the
	// target isn't dialled; retried at d, it is.
	failedAt := now
	for n := 1; n <= 4; n++ {
		d := checkBackoffMin << (n - 1)
		now = failedAt.Add(d/2 - time.Second)
		listen()
		dialsWithin(int32(n))
		now = failedAt.Add(d)
		listen()
		dialsWithin(int32(n + 1))
		failedAt = now
	}
}

// The waits between checks of a failing target are random and grow to
// checkBackoffMax, so retries can't settle into a fixed period.
func TestTargetCheckWaitsGrowAtRandom(t *testing.T) {
	d := checkBackoffMin
	for n := 1; n <= 80; n++ {
		if n > 1 {
			d = min(2*d, checkBackoffMax)
		}
		seen := map[time.Duration]bool{}
		for range 20 {
			w := checkBackoff(n)
			if w < d/2 || w > d {
				t.Fatalf("wait after %d failures: %s, want within [%s, %s]", n, w, d/2, d)
			}
			seen[w] = true
		}
		if len(seen) < 2 {
			t.Fatalf("wait after %d failures: always %v", n, seen)
		}
	}
}

// While Listen checks its target, its port is closed: held, it would take
// connections it answers nothing on for as long as the check runs, which
// a prober would see, and a supervisor would hand them all over the moment
// it starts serving, before its workers know the listener.
func TestTheListenersPortIsClosedWhileItsTargetIsChecked(t *testing.T) {
	site, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = site.Close() })
	checking := make(chan struct{})
	go func() {
		c, err := site.Accept()
		if err != nil {
			return
		}
		close(checking)
		time.Sleep(500 * time.Millisecond)
		_ = c.Close() // no TLS: the check fails
	}()
	addr := closedPort(t)
	settings := mustMarshal(t, &transportv1.RealityListenSettings{
		PrivateKey: newKeys(t).private, Target: site.Addr().String(), ServerNames: []string{serverName},
	})
	listened := make(chan error, 1)
	go func() {
		l, err := newTransport(Options{}).Listen(t.Context(), transport.ListenConfig{Address: addr, Settings: settings}, transport.Admission{Peers: transport.NewPeerTable()})
		if err == nil {
			_ = l.Close()
		}
		listened <- err
	}()
	select {
	case <-checking:
	case <-time.After(5 * time.Second):
		t.Fatal("Listen didn't check the target")
	}
	if c, err := net.DialTimeout("tcp4", addr, time.Second); err == nil {
		_ = c.Close()
		t.Errorf("%s took a connection while its target was checked", addr)
	}
	if err := <-listened; err == nil {
		t.Fatal("listened with a target that doesn't speak TLS")
	}
}
