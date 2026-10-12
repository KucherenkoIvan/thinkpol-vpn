package dataplane_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
)

// fakeInterface records the configurations applied to the overlay's
// interface; failing makes the next calls fail, and hold, if set, keeps
// the next call until it is closed (entered hears when it is held).
type fakeInterface struct {
	mu            sync.Mutex
	applied       []netcfg.Config
	failing       int
	hold, entered chan struct{}
}

func (f *fakeInterface) Apply(_ context.Context, c netcfg.Config) error {
	f.mu.Lock()
	hold, entered := f.hold, f.entered
	f.hold = nil
	f.mu.Unlock()
	if hold != nil {
		entered <- struct{}{}
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, c)
	if f.failing > 0 {
		f.failing--
		return errKernel
	}
	return nil
}

func (f *fakeInterface) fail(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = n
}

func (f *fakeInterface) calls() []netcfg.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.applied)
}

func (f *fakeInterface) DefaultRoute(context.Context, netcfg.Family) (netcfg.Route, error) {
	return netcfg.Route{}, netcfg.ErrNoDefaultRoute
}

func (f *fakeInterface) Watch(context.Context) (<-chan struct{}, error) {
	return nil, netcfg.ErrClosed
}

func (f *fakeInterface) Survey(context.Context) (netcfg.Survey, error) { return netcfg.Survey{}, nil }
func (f *fakeInterface) Close() error                                  { return nil }

// linkTUN is a virtual TUN whose link events the test sends.
type linkTUN struct {
	tun.Device
	events chan tun.Event
	once   sync.Once
}

func (l *linkTUN) Events() <-chan tun.Event { return l.events }

func (l *linkTUN) Close() error {
	err := l.Device.Close()
	l.once.Do(func() { close(l.events) })
	return err
}

// syncBuffer is a log destination safe for the engine's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startLinkEngine starts device-a's engine on a virtual TUN whose link
// events the test sends, with a fake interface, and applies its section.
func startLinkEngine(t *testing.T, log *syncBuffer) (*dataplane.Engine, *node, *linkTUN, *fakeInterface) {
	t.Helper()
	a, _, _ := m0()
	reg, err := transport.NewRegistry(memory.NewNetwork(memory.Datagram))
	if err != nil {
		t.Fatal(err)
	}
	dev := &linkTUN{Device: tuntest.NewChannelTUN().TUN(), events: make(chan tun.Event, 8)}
	ifc := &fakeInterface{}
	e, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID: a.id, Space: testSpace, WireGuardKey: a.key, Registry: reg, TUN: dev, Interface: ifc, Path: fastPaths,
		Log: slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if err := e.Apply(context.Background(), a.section); err != nil {
		t.Fatal(err)
	}
	return e, a, dev, ifc
}

// calledAtLeast waits until the fake interface has had n calls.
func calledAtLeast(t *testing.T, ifc *fakeInterface, n int) []netcfg.Config {
	t.Helper()
	for deadline := time.Now().Add(wait); ; time.Sleep(10 * time.Millisecond) {
		if c := ifc.calls(); len(c) >= n {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d calls to the interface, want %d", len(ifc.calls()), n)
		}
	}
}

// An Apply that runs while a link event waits for its re-apply wins: the
// re-apply carries the new section's configuration, not the one in place
// when the event came.
func TestAReapplyCarriesTheConfigurationOfAnApplyRacingIt(t *testing.T) {
	var log syncBuffer
	e, a, dev, ifc := startLinkEngine(t, &log)
	next := a.section
	next.Node.IPv4 = netip.MustParseAddr("100.64.0.9")
	hold, entered := make(chan struct{}), make(chan struct{}, 1)
	ifc.mu.Lock()
	ifc.hold, ifc.entered = hold, entered
	ifc.mu.Unlock()
	applied := make(chan error, 1)
	go func() { applied <- e.Apply(context.Background(), next) }()
	<-entered // the Apply is configuring the interface
	dev.events <- tun.EventUp
	time.Sleep(500 * time.Millisecond) // past the debounce: the re-apply waits for the Apply
	close(hold)
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	calls := calledAtLeast(t, ifc, 3)
	want := netip.MustParsePrefix("100.64.0.9/16")
	if got := calls[1].Interfaces[0]; !got.Up || !slices.Contains(got.Addrs, want) {
		t.Fatalf("Apply configured %+v, want %v", got, want)
	}
	if got := calls[2].Interfaces[0]; got.Up || !slices.Contains(got.Addrs, want) {
		t.Fatalf("re-applied %+v, want the new section's %v", got, want)
	}
}

// A re-apply that fails is retried while the link is up, and only the
// first failure of a run of them is a warning; a link that goes down stops
// the retries until it comes up again. Only successes are counted.
func TestAFailedReapplyIsRetriedWhileTheLinkIsUp(t *testing.T) {
	var log syncBuffer
	e, _, dev, ifc := startLinkEngine(t, &log)
	dataplane.SetInterfaceTimingForTest(e, 50*time.Millisecond, 0, 200*time.Millisecond)
	warnings := func() int { return strings.Count(log.String(), "level=WARN msg=\"overlay interface: re-applying") }

	ifc.fail(1)
	dev.events <- tun.EventUp
	calledAtLeast(t, ifc, 3) // the Apply, a failed re-apply, its retry
	for deadline := time.Now().Add(wait); e.Status().InterfaceReapplies != 1; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("status counts %d re-applies, want the one that succeeded", e.Status().InterfaceReapplies)
		}
	}
	if n := warnings(); n != 1 {
		t.Fatalf("%d warnings, want 1:\n%s", n, log.String())
	}

	ifc.fail(1 << 20)
	dev.events <- tun.EventUp
	calledAtLeast(t, ifc, 6) // three failures in a row
	if n := warnings(); n != 2 {
		t.Fatalf("%d warnings after a run of failures, want one more:\n%s", n, log.String())
	}
	dev.events <- tun.EventDown
	time.Sleep(500 * time.Millisecond) // the router has seen it
	n := len(ifc.calls())
	time.Sleep(time.Second) // five retries' worth
	if got := len(ifc.calls()); got != n {
		t.Fatalf("%d re-applies while the link was down", got-n)
	}

	ifc.fail(0)
	dev.events <- tun.EventUp
	calledAtLeast(t, ifc, n+1)
	for deadline := time.Now().Add(wait); e.Status().InterfaceReapplies != 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("status counts %d re-applies, want 2", e.Status().InterfaceReapplies)
		}
	}
}

// A TUN whose link goes down and comes back gets its addresses and MTU
// re-applied once per bounce, without a new map; a link that goes down
// alone is left alone.
func TestALinkBounceReappliesTheInterface(t *testing.T) {
	a, _, _ := m0()
	reg, err := transport.NewRegistry(memory.NewNetwork(memory.Datagram))
	if err != nil {
		t.Fatal(err)
	}
	dev := &linkTUN{Device: tuntest.NewChannelTUN().TUN(), events: make(chan tun.Event, 8)}
	ifc := &fakeInterface{}
	var log syncBuffer
	e, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID: a.id, Space: testSpace, WireGuardKey: a.key, Registry: reg, TUN: dev, Interface: ifc, Path: fastPaths,
		Log: slog.New(slog.NewTextHandler(&log, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if err := e.Apply(context.Background(), a.section); err != nil {
		t.Fatal(err)
	}
	first := ifc.calls()
	if len(first) != 1 || len(first[0].Interfaces) != 1 {
		t.Fatalf("Apply configured %+v, want the TUN", first)
	}
	want := first[0].Interfaces[0]
	if !want.Up || want.MTU == 0 || len(want.Addrs) != 2 {
		t.Fatalf("Apply configured %+v, want both addresses, an MTU and the link up", want)
	}

	dev.events <- tun.EventDown
	dev.events <- tun.EventUp
	for deadline := time.Now().Add(wait); len(ifc.calls()) < 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the bounce wasn't re-applied")
		}
	}
	time.Sleep(time.Second) // nothing more comes of it
	calls := ifc.calls()
	if len(calls) != 2 {
		t.Fatalf("%d re-applies after one bounce, want 1: %+v", len(calls)-1, calls[1:])
	}
	again := want
	again.Up = false // the link is up already, and a link that went down again stays down
	if got := calls[1].Interfaces; len(got) != 1 || got[0].Name != again.Name || got[0].MTU != again.MTU ||
		got[0].Up || !slices.Equal(got[0].Addrs, again.Addrs) {
		t.Fatalf("re-applied %+v, want %+v", got, again)
	}
	if n := e.Status().InterfaceReapplies; n != 1 {
		t.Fatalf("status counts %d re-applies, want 1", n)
	}
	if !strings.Contains(log.String(), `msg="overlay interface re-applied" reason="link event"`) {
		t.Fatalf("no re-apply in the log:\n%s", log.String())
	}

	// Down alone: nothing to put back until it comes up.
	dev.events <- tun.EventDown
	time.Sleep(time.Second)
	if n := len(ifc.calls()); n != 2 {
		t.Fatalf("a link going down was re-applied: %d calls", n)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(ifc.calls()); n != 2 {
		t.Fatalf("closing re-applied the interface: %d calls", n)
	}
}

// A link event before the first Apply has nothing to re-apply.
func TestALinkEventBeforeTheFirstApplyChangesNothing(t *testing.T) {
	a, _, _ := m0()
	reg, err := transport.NewRegistry(memory.NewNetwork(memory.Datagram))
	if err != nil {
		t.Fatal(err)
	}
	dev := &linkTUN{Device: tuntest.NewChannelTUN().TUN(), events: make(chan tun.Event, 8)}
	ifc := &fakeInterface{}
	e, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID: a.id, Space: testSpace, WireGuardKey: a.key, Registry: reg, TUN: dev, Interface: ifc, Path: fastPaths,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	dev.events <- tun.EventUp
	time.Sleep(time.Second)
	if c := ifc.calls(); len(c) != 0 || e.Status().InterfaceReapplies != 0 {
		t.Fatalf("configured %+v before any Apply", c)
	}
}
