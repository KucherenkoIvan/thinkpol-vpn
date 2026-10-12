package dataplane_test

import (
	"bytes"
	"context"
	"log/slog"
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
// interface.
type fakeInterface struct {
	mu      sync.Mutex
	applied []netcfg.Config
}

func (f *fakeInterface) Apply(_ context.Context, c netcfg.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, c)
	return nil
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
