package reality

import (
	"errors"
	"io"
	"net"
	"slices"
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
	tg := newIdleTarget(t, idle, false)
	l := listenTo(t, New(Options{}), tg, newKeys(t))
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

// Once the target closed its side, a splice gives a client that stays
// silent spliceLinger, then closes both connections.
func TestASpliceEndsOnceTheTargetClosedAndTheClientStaysSilent(t *testing.T) {
	linger := spliceLinger
	spliceLinger = 200 * time.Millisecond
	t.Cleanup(func() { spliceLinger = linger })
	tg := newIdleTarget(t, 300*time.Millisecond, true)
	l := listenTo(t, New(Options{}), tg, newKeys(t))
	drain(tg.ended)

	c := probe(t, l.Addr().String(), nil)
	closedWithin(t, c, 5*time.Second) // the target's FIN
	select {
	case <-tg.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the splice still holds the target's connection")
	}
}

// Closing the listener ends its live splices.
func TestClosingTheListenerEndsItsSplices(t *testing.T) {
	tg := newIdleTarget(t, time.Minute, false)
	l := listenTo(t, New(Options{}), tg, newKeys(t))
	sent := []byte("GET / HTTP/1.1\r\n\r\n")
	c := probe(t, l.Addr().String(), sent)
	if !tg.receivedExactly(sent) {
		t.Fatal("the probe wasn't spliced to the target")
	}
	_ = l.Close()
	closedWithin(t, c, 3*time.Second)
}

func drain(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
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
		_, err := New(Options{}).Listen(t.Context(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}, transport.Admission{Peers: transport.NewPeerTable()})
		if err == nil {
			t.Fatal("listening with an unreachable target")
		}
	})
	t.Run("stalled", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				t.Cleanup(func() { _ = c.Close() })
			}
		}()
		if err := detect(t.Context(), ln.Addr().String(), names, 300*time.Millisecond); err == nil {
			t.Fatal("detected the records of a target that never answers")
		}
		// Forgotten: the next Listen detects again.
		if _, ok := xreality.GlobalPostHandshakeRecordsLens.Load(recordsKey(ln.Addr().String(), serverName, 0)); ok {
			t.Error("a failed detection is still cached")
		}
	})
	t.Run("a site", func(t *testing.T) {
		if err := detect(t.Context(), theTarget(t).addr(), names, detectWait); err != nil {
			t.Fatal(err)
		}
	})
}

// A refused entry sharing a short id with a valid one drops the short id:
// neither is taken, and both are reported.
func TestARefusedEntryDropsItsShortID(t *testing.T) {
	tr := New(Options{})
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
	ahead := New(Options{Now: func() time.Time { return time.Now().Add(2 * time.Minute) }})
	l := listenFor(t, ahead, k, 60, peerLink(id))
	if _, err := dial(t, New(Options{}), l.Addr().String(), k, id); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("dial sealed now through a 1-minute window 2 minutes ahead: %v, want %v", err, ErrNotAuthenticated)
	}
	ok := New(Options{Now: func() time.Time { return time.Now().Add(30 * time.Second) }})
	l = listenFor(t, ok, k, 60, peerLink(id))
	if _, err := dial(t, New(Options{}), l.Addr().String(), k, id); err != nil {
		t.Errorf("dial sealed now through a 1-minute window 30 s ahead: %v", err)
	}
}
