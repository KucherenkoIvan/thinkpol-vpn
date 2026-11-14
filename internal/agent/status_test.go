package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// deviceNode is device b of the test space as `thinkpol up` runs it, on
// virtual TUNs.
type deviceNode struct {
	*runningNode
	node *Node
	// failTUN makes the next TUN fail to come up.
	failTUN chan struct{}
	// events are the node's.
	events *heardEvents
}

// deviceOpt adjusts device b: prepare sets its config and platform
// (every host fake) before it is prepared, node sees the prepared node
// before it runs, and tuning its data plane's tuning (fast paths and
// retries already). It runs with a route table, as a device does: the
// test platform's does nothing unless prepare gives it another.
type deviceOpt struct {
	prepare func(*Config, *Platform)
	node    func(*Node)
	tuning  func(*tuning)
}

// startDevice starts device b with opts.
func startDevice(t *testing.T, s *testSpace, reg *transport.Registry, connect bool, opts ...deviceOpt) *deviceNode {
	t.Helper()
	cfg := testConfig(s.stateDir(t, s.b, 1))
	cfg.Connect = connect
	rn := newRunningNode()
	failTUN := make(chan struct{}, 1)
	logs, err := NewLogs("debug", rn.log)
	if err != nil {
		t.Fatal(err)
	}
	plat := testPlatform()
	plat.NewConfigurator = func(netcfg.Owner) (netcfg.Configurator, error) { return rn.ifc, nil }
	plat.NewTUN = rn.virtualTUN(failTUN)
	for _, o := range opts {
		if o.prepare != nil {
			o.prepare(&cfg, &plat)
		}
	}
	n, err := Prepare(cfg, logs, plat)
	if err != nil {
		t.Fatal(err)
	}
	n.takeConnectChoice() // as Adapters does, under the host lock
	rn.status = n.Status
	d := &deviceNode{runningNode: rn, node: n, failTUN: failTUN, events: newHeardEvents(t)}
	n.Subscribe(d.events.add)
	for _, o := range opts {
		if o.node != nil {
			o.node(n)
		}
	}
	n.tuning = tuning{path: fastPaths, retryAfter: testRetry}
	for _, o := range opts {
		if o.tuning != nil {
			o.tuning(&n.tuning)
		}
	}
	go func() { rn.done <- n.run(rn.ctx, reg, rn.maps) }()
	t.Cleanup(func() {
		rn.stop()
		select {
		case <-rn.done:
			if n.conn.refused != 0 {
				t.Errorf("the connection refused %d moves", n.conn.refused)
			}
		case <-time.After(10 * time.Second):
			t.Error("the node didn't stop")
		}
		if t.Failed() {
			t.Logf("log:\n%s", rn.log)
		}
	})
	return d
}

func (d *deviceNode) connection(t *testing.T, want Connection) Status {
	t.Helper()
	var st Status
	eventually(t, func() bool { st = d.node.Status(); return st.Connection == want })
	return st
}

func TestADeviceConnectsAndDisconnects(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, false)
	a4, a6 := overlay(1)
	b4, b6 := overlay(2)
	ctx := context.Background()

	// Started disconnected: nothing runs, the maps are followed.
	st := b.connection(t, Disconnected)
	if st.DataPlane != nil || st.Mode != ModeDevice || st.Space != s.id || st.MapVersion != 1 {
		t.Fatalf("status %+v", st)
	}
	if h := st.Health(); h.Level != HealthDown || !slices.Equal(h.Problems, []Problem{ProblemDisconnected}) {
		t.Fatalf("health %+v", h)
	}
	b.maps <- s.build(t, 2)
	eventually(t, func() bool { return b.node.Status().MapVersion == 2 })
	if b.tuns.Load() != 0 {
		t.Fatal("a TUN while disconnected")
	}

	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	st = b.connection(t, Connected)
	if st.DataPlane == nil || !st.DataPlane.IPv6 || len(st.DataPlane.Peers) != 1 || st.DataPlane.Peers[0].ID != s.a.ID {
		t.Fatalf("data plane %+v", st.DataPlane)
	}
	b.ping(t, b4, a4)
	b.ping(t, b6, a6)
	eventually(t, func() bool { return b.node.Status().Health().Level == HealthOK })
	if err := b.node.Connect(ctx); err != nil || b.tuns.Load() != 1 {
		t.Fatalf("connecting again: %v, %d TUNs", err, b.tuns.Load())
	}

	if err := b.node.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if st := b.node.Status(); st.Connection != Disconnected || st.DataPlane != nil {
		t.Fatalf("after Disconnect: %+v", st)
	}
	if b.answered(b4, a4, 500*time.Millisecond) {
		t.Fatal("answered while disconnected")
	}

	// A start that fails is Connect's error, and the device stays down.
	b.failTUN <- struct{}{}
	var se *StartError
	if err := b.node.Connect(ctx); !errors.As(err, &se) || se.Step != StepTUN {
		t.Fatalf("got %v, want a StartError at %s", err, StepTUN)
	}
	b.connection(t, Disconnected)

	// Back up on the latest map.
	b.maps <- s.build(t, 3)
	eventually(t, func() bool { return b.node.Status().MapVersion == 3 })
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	b.ping(t, b4, a4)
	b.applied(t, 3)

	// Removed while connected: it waits, and is back with the next map
	// that has it.
	b.maps <- s.buildWithout(t, 4, s.b)
	eventually(t, func() bool { st = b.node.Status(); return st.MapVersion == 4 && st.Connection == Connecting })
	if !st.Removed || st.DataPlane != nil || !slices.Contains(st.Health().Problems, ProblemRemoved) {
		t.Fatalf("removed: %+v", st)
	}
	b.maps <- s.build(t, 5)
	b.connection(t, Connected)
	b.ping(t, b4, a4)
	// Up each time it came up, on the map it came up on; nothing for the
	// start that failed.
	b.events.are(t, Event{EventConnected, 2}, Event{EventConnected, 3},
		Event{EventRemovedFromSpace, 4}, Event{EventBackInSpace, 5}, Event{EventConnected, 5})

	// Stopped, it says so.
	b.stop()
	if err := <-b.done; err != nil {
		t.Fatal(err)
	}
	if st := b.node.Status(); st.Connection != Disconnected || st.DataPlane != nil {
		t.Fatalf("stopped: %+v", st)
	}
	b.done <- nil // for the cleanup
	if err := b.node.Disconnect(ctx); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("got %v, want ErrNotRunning", err)
	}
}

// A status read while the data plane stops (removed from the space, then
// disconnected) shows the state before or the state after, never a mix
// such as "connecting, old version, not removed".
func TestStatusIsWholeWhileTheDataPlaneStops(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, true)
	b.connection(t, Connected)

	type view struct {
		version   uint64
		conn      Connection
		removed   bool
		dataPlane bool
		retrying  bool
	}
	seen := map[view]int{}
	stop, polled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(polled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			st := b.node.Status()
			seen[view{st.MapVersion, st.Connection, st.Removed, st.DataPlane != nil, st.Retrying}]++
		}
	}()
	b.maps <- s.buildWithout(t, 2, s.b)
	eventually(t, func() bool { st := b.node.Status(); return st.MapVersion == 2 && st.Removed })
	b.maps <- s.build(t, 3)
	eventually(t, func() bool { st := b.node.Status(); return st.MapVersion == 3 && st.Connection == Connected })
	if err := b.node.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(stop)
	<-polled

	whole := []view{
		{1, Connected, false, true, false},
		{2, Connecting, true, false, false},
		{3, Connected, false, true, false},
		{3, Disconnected, false, false, false},
	}
	for v, n := range seen {
		if !slices.Contains(whole, v) {
			t.Errorf("read %d times: version %d, %s, removed %v, data plane %v, retrying %v",
				n, v.version, v.conn, v.removed, v.dataPlane, v.retrying)
		}
	}
}

// A device removed while it was down keeps a Connect for when it is back.
func TestARemovedDeviceConnectsOnceBack(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, false, deviceOpt{prepare: func(c *Config, _ *Platform) {
		writeFile(t, filepath.Join(c.StateDir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
	}})
	ctx := context.Background()
	if st := b.node.Status(); !st.Removed || st.Mode != ModeDevice {
		t.Fatalf("status %+v", st)
	}
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if st := b.node.Status(); st.Connection != Connecting {
		t.Fatalf("status %+v", st)
	}
	b.maps <- s.build(t, 2)
	st := b.connection(t, Connected)
	if st.Mode != ModeDevice || st.Removed || st.MapVersion != 2 {
		t.Fatalf("status %+v", st)
	}
	b4, _ := overlay(2)
	a4, _ := overlay(1)
	b.ping(t, b4, a4)
	if got := b.log.String(); strings.Count(got, "back in space") != 1 {
		t.Errorf("log %q", got)
	}
	b.events.are(t, Event{EventRemovedFromSpace, 1}, Event{EventBackInSpace, 2}, Event{EventConnected, 2})
}

// A map whose rules the OS routing table can't take is an event, told
// once while it fails; the Apply is retried.
func TestARouteTableNotEnforcedIsAnEvent(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	table := &wantsTable{}
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(_ *Config, p *Platform) {
			p.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) { return table, nil }
		},
	})
	b.connection(t, Connected)
	table.mu.Lock()
	table.failing = 2
	table.mu.Unlock()
	b.maps <- s.build(t, 2)
	b.events.are(t, Event{EventConnected, 1}, Event{EventRouteTableNotEnforced, 2})
	b.applied(t, 2)
}

// The route table failing on its own is told as the status says so; once
// it recovered on its own, failing again is told again.
func TestARouteTableNotEnforcedIsToldAgainAfterItRecovered(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	table := &wantsTable{}
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(_ *Config, p *Platform) {
			p.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) { return table, nil }
		},
	})
	b.connection(t, Connected)
	// Each flip lands as the map's Apply enforces, before the publish
	// after it; the runner takes the maps in order.
	table.breakAtNextEnforce(true)
	b.maps <- s.build(t, 2)
	b.events.are(t, Event{EventConnected, 1}, Event{EventRouteTableNotEnforced, 2})
	table.breakAtNextEnforce(false)
	b.maps <- s.build(t, 3)
	eventually(t, func() bool { st := b.node.Status(); return st.MapVersion == 3 && st.DataPlane.RouteTable.Error == "" })
	table.breakAtNextEnforce(true)
	b.maps <- s.build(t, 4)
	b.events.are(t, Event{EventConnected, 1}, Event{EventRouteTableNotEnforced, 2}, Event{EventRouteTableNotEnforced, 4})
}

// A node that returns reads disconnected: its first start failed, or it
// stopped while it waited out of its space.
func TestAStoppedNodeReadsDisconnected(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))

	failed := startDevice(t, s, reg, true, deviceOpt{prepare: func(_ *Config, p *Platform) {
		p.NewTUN = func(string, int) (wgtun.Device, error) { return nil, errors.New("no TUN today") }
	}})
	if err := <-failed.done; err == nil {
		t.Fatal("the first start didn't fail")
	}
	failed.done <- nil // for the cleanup
	if st := failed.node.Status(); st.Connection != Disconnected {
		t.Errorf("after a failed first start: %+v", st)
	}

	removed := startDevice(t, s, reg, true, deviceOpt{prepare: func(c *Config, _ *Platform) {
		writeFile(t, filepath.Join(c.StateDir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
	}})
	removed.connection(t, Connecting)
	removed.stop()
	if err := <-removed.done; err != nil {
		t.Fatal(err)
	}
	removed.done <- nil
	if st := removed.node.Status(); st.Connection != Disconnected || !st.Removed {
		t.Errorf("stopped while removed: %+v", st)
	}
	removed.events.are(t, Event{EventRemovedFromSpace, 1})
}

// A subscriber that reads the status as it hears an event sees what the
// event says.
func TestTheStatusShowsWhatAnEventSays(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	sys := &fakeSystem{failSets: 1}
	type seen struct {
		ev Event
		st Status
	}
	var mu sync.Mutex
	var heard []seen
	b := startDevice(t, s, reg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			p.SetSystemDNS = sys.Set
			p.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) { return nil, nil }
		},
		node: func(n *Node) {
			n.Subscribe(func(ev Event) {
				st := n.Status()
				mu.Lock()
				defer mu.Unlock()
				heard = append(heard, seen{ev, st})
			})
		},
		tuning: func(t *tuning) { t.dnsPort = 5353 },
	})
	b.events.are(t, Event{EventConnected, 1}, Event{EventDNSUnprotected, 1})
	b.maps <- s.buildWithout(t, 2, s.b)
	b.events.are(t, Event{EventConnected, 1}, Event{EventDNSUnprotected, 1}, Event{EventRemovedFromSpace, 2})
	b.maps <- s.build(t, 3)
	b.events.are(t, Event{EventConnected, 1}, Event{EventDNSUnprotected, 1}, Event{EventRemovedFromSpace, 2},
		Event{EventBackInSpace, 3}, Event{EventConnected, 3})
	eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(heard) == 5 })

	mu.Lock()
	defer mu.Unlock()
	for _, h := range heard {
		st := h.st
		var shows bool
		switch h.ev.Kind {
		case EventConnected:
			shows = st.Connection == Connected && st.DataPlane != nil
		case EventDNSUnprotected:
			shows = st.Connection == Connected && st.DNSUnprotected
		case EventRemovedFromSpace:
			shows = st.Removed && st.Connection == Connecting && st.DataPlane == nil
		case EventBackInSpace:
			shows = !st.Removed
		}
		if !shows || st.MapVersion != h.ev.MapVersion {
			t.Errorf("%s at version %d, status %+v", h.ev.Kind, h.ev.MapVersion, st)
		}
	}
}

// A subscriber's panic is logged; the node goes on, and so do the other
// subscribers.
func TestAPanickingSubscriberDoesNotStopTheNode(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	after := newHeardEvents(t)
	b := startDevice(t, s, reg, true, deviceOpt{node: func(n *Node) {
		n.Subscribe(func(Event) { panic("a subscriber's bug") })
		n.Subscribe(after.add)
	}})
	b.events.are(t, Event{EventConnected, 1})
	// Told in order: the subscriber after the panicking one hears the
	// event once the panic was logged.
	after.are(t, Event{EventConnected, 1})
	if !logMatches(b.log.String(), `level=ERROR msg="an event subscriber panicked"`) {
		t.Error("the subscriber's panic isn't logged")
	}
	b4, _ := overlay(2)
	a4, _ := overlay(1)
	b.ping(t, b4, a4)
}

func TestAServerRefusesConnect(t *testing.T) {
	s := newTestSpace(t)
	n, err := Prepare(serverConfig(s.stateDir(t, s.a, 1)), Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []func(context.Context) error{n.Connect, n.Disconnect} {
		if err := f(context.Background()); !errors.Is(err, ErrServerMode) {
			t.Fatalf("got %v, want ErrServerMode", err)
		}
	}
	if st := n.Status(); st.Connection != Serving || st.Mode != ModeServer {
		t.Fatalf("status %+v", st)
	}
}

type stubWorkerReporter struct {
	workers []supervisor.WorkerInfo
}

func (s stubWorkerReporter) Workers() []supervisor.WorkerInfo   { return s.workers }
func (stubWorkerReporter) Listeners() []supervisor.ListenerInfo { return nil }
func (stubWorkerReporter) Egress() supervisor.EgressInfo        { return supervisor.EgressInfo{} }

// The status carries why a worker's process ended as its code, not the
// error's text.
func TestWorkerLastExitInStatus(t *testing.T) {
	space := netmap.SpaceID{0x01}
	st := (&report{
		mode: ModeServer,
		workers: stubWorkerReporter{workers: []supervisor.WorkerInfo{{Space: space, Ready: false, Starts: 1,
			LastExit: "start: no such file", LastExitReason: supervisor.ExitSpawnFailed}}},
	}).status()
	if len(st.Workers) != 1 || st.Workers[0].LastExit != supervisor.ExitSpawnFailed {
		t.Fatalf("workers %+v", st.Workers)
	}
}

func TestHealth(t *testing.T) {
	up := path.NeighborStatus{Up: true}
	down := path.NeighborStatus{}
	for _, tc := range []struct {
		name string
		st   Status
		want Health
	}{
		{"connected", Status{Connection: Connected, DataPlane: &dataplane.Status{Neighbors: []path.NeighborStatus{up}}}, Health{}},
		{"no neighbors yet", Status{Connection: Connected, DataPlane: &dataplane.Status{}}, Health{}},
		{"disconnected", Status{Connection: Disconnected}, Health{HealthDown, []Problem{ProblemDisconnected}}},
		{"starting", Status{Connection: Connecting}, Health{HealthDown, []Problem{ProblemStarting}}},
		{"retrying", Status{Connection: Connecting, Retrying: true}, Health{HealthDown, []Problem{ProblemRetrying}}},
		{"removed", Status{Connection: Connecting, Removed: true}, Health{HealthDown, []Problem{ProblemRemoved}}},
		{"no link up", Status{Connection: Connected, DataPlane: &dataplane.Status{Neighbors: []path.NeighborStatus{down, down}}},
			Health{HealthDown, []Problem{ProblemNoLinkUp}}},
		{"one down", Status{Connection: Connected, DataPlane: &dataplane.Status{Neighbors: []path.NeighborStatus{up, down},
			LastApplyError: dataplane.StepRouter, Skipped: []dataplane.Skip{{}}}},
			Health{HealthDegraded, []Problem{ProblemApplyFailed, ProblemNeighborDown, ProblemSkipped}}},
		{"route table not enforced", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Error: dataplane.RouteTableReapplyFailed, Routes: 9}}},
			Health{HealthDown, []Problem{ProblemRouteTable}}},
		{"rules ahead of the route table", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, RulesAhead: 2}}},
			Health{HealthDegraded, []Problem{ProblemRulesAhead}}},
		{"overlay addresses taken around the route table", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, OverlayAhead: 1}}},
			Health{HealthDown, []Problem{ProblemOverlayRoutesAhead}}},
		{"a corrupt route record, its routes left", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, CorruptRecords: 1, UnownedRoutes: 3}}},
			Health{HealthDegraded, []Problem{ProblemRouteRecordsCorrupt}}},
		{"a corrupt route record, no routes left", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, CorruptRecords: 1}}},
			Health{HealthOK, nil}},
		{"unowned routes without a corrupt record (another program's)", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, UnownedRoutes: 3}}},
			Health{HealthOK, nil}},
		{"leak guard failing, routes in place", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, GuardError: dataplane.RouteTableGuardFailed}}},
			Health{HealthDegraded, []Problem{ProblemGuard}}},
		{"no nf_tables: connected, a loud warning", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, GuardError: dataplane.RouteTableGuardUnsupported}}},
			Health{HealthDegraded, []Problem{ProblemGuardUnsupported}}},
		{"the default rule's exit unanswered", Status{Connection: Connected, ExitsUnanswered: 1, DefaultExitUnanswered: true, DataPlane: &dataplane.Status{
			Neighbors: []path.NeighborStatus{up}}},
			Health{HealthDown, []Problem{ProblemExitNoHandshake}}},
		{"another exit unanswered", Status{Connection: Connected, ExitsUnanswered: 1, DataPlane: &dataplane.Status{
			Neighbors: []path.NeighborStatus{up}}},
			Health{HealthDegraded, []Problem{ProblemExitNoHandshake}}},
		{"server", Status{Connection: Serving, Workers: []WorkerStatus{{Ready: true, Starts: 1}}}, Health{}},
		{"server worker down", Status{Connection: Serving, Workers: []WorkerStatus{{Ready: true, Starts: 3}, {}},
			PublicListeners: []PublicListenerStatus{{Rejected: 1}}},
			Health{HealthDown, []Problem{ProblemWorkerDown, ProblemWorkerRestarts, ProblemLinksRejected}}},
		{"server retrying", Status{Connection: Serving, Retrying: true}, Health{HealthDegraded, []Problem{ProblemRetrying}}},
	} {
		if got := tc.st.Health(); got.Level != tc.want.Level || !slices.Equal(got.Problems, tc.want.Problems) {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// A device whose start failed and waits for a retry tries again on
// Connect, and says why it failed.
func TestConnectStartsADeviceThatIsRetrying(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, false)
	ctx := context.Background()
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	// Removed and back: its start fails once, so it is up-but-retrying.
	b.maps <- s.buildWithout(t, 2, s.b)
	b.connection(t, Connecting)
	b.failTUN <- struct{}{}
	b.maps <- s.build(t, 3)
	eventually(t, func() bool { st := b.node.Status(); return st.Retrying && st.Connection == Connecting })
	b.failTUN <- struct{}{}
	var se *StartError
	if err := b.node.Connect(ctx); !errors.As(err, &se) {
		t.Fatalf("got %v, want a StartError", err)
	}
	if st := b.node.Status(); st.Connection != Connecting || !st.Retrying {
		t.Fatalf("after a failed Connect: %+v", st)
	}
	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if st := b.node.Status(); st.Connection != Connected {
		t.Fatalf("after Connect: %+v", st)
	}
}

func TestRulePresetIsStoredByTheService(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, true)
	ctx := context.Background()
	dir := b.node.cfg.StateDir
	file := filepath.Join(dir, DeviceFile)
	st := b.connection(t, Connected)
	if st.RulePreset != "space" || !st.RulesEnforced || st.PresetUnavailable {
		t.Fatalf("status %+v", st)
	}
	if err := b.node.SetRulePreset(ctx, "nope"); !errors.Is(err, ErrUnknownPreset) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused preset wrote the file: %v", err)
	}
	// The test space has no chain to build "everything" from: the choice
	// is kept and enforced failing closed, and said so.
	if err := b.node.SetRulePreset(ctx, "everything"); !errors.Is(err, ErrPresetUnavailable) {
		t.Fatalf("got %v, want ErrPresetUnavailable", err)
	}
	if got, err := os.ReadFile(file); err != nil || !strings.Contains(string(got), `"rule_preset": "everything"`) {
		t.Fatalf("file %q, %v", got, err)
	}
	if fi, _ := os.Lstat(file); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	st = b.node.Status()
	if st.RulePreset != "everything" || !st.PresetUnavailable || !slices.Contains(st.Health().Problems, ProblemPresetUnavailable) {
		t.Fatalf("status %+v", st)
	}
	wantPreset(t, b.node, "everything")
	// Read back at the next start.
	n, err := Prepare(b.node.cfg, Logs{}, testPlatform())
	if err != nil || n.Status().RulePreset != "everything" {
		t.Fatalf("restart: %v", err)
	}
	if err := b.node.SetRulePreset(ctx, "space"); err != nil {
		t.Fatal(err)
	}
	if st := b.node.Status(); st.RulePreset != "space" || st.PresetUnavailable {
		t.Fatalf("status %+v", st)
	}
	wantPreset(t, b.node, "space")
	// A server has no rules of its own.
	if a, err := Prepare(serverConfig(s.stateDir(t, s.a, 1)), Logs{}, testPlatform()); err != nil || !errors.Is(a.SetRulePreset(ctx, "everything"), ErrServerMode) {
		t.Fatalf("server: %v", err)
	}
}

// A preset set before the node's data plane runs is taken once it does:
// the request never holds up the run that would take it, and nothing
// shows it before the data plane follows it.
func TestARulePresetSetBeforeTheNodeRunsIsTaken(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	set := make(chan error, 1)
	b := startDevice(t, s, reg, true, deviceOpt{node: func(n *Node) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		go func() {
			defer cancel()
			set <- n.SetRulePreset(ctx, "all-but-domestic")
		}()
		// While SetRulePreset waits for the data plane, nothing is
		// stored or shown.
		for deadline := time.Now().Add(100 * time.Millisecond); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			select {
			case err := <-set:
				t.Fatalf("SetRulePreset returned %v before the data plane ran", err)
			default:
			}
			wantPreset(t, n, "space")
		}
	}})
	select {
	case err := <-set:
		if err != nil && !errors.Is(err, ErrPresetUnavailable) {
			t.Fatalf("SetRulePreset: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("SetRulePreset never returned")
	}
	b.connection(t, Connected)
	wantPreset(t, b.node, "all-but-domestic")
}

// A preset request whose caller gives up before the data plane takes it
// changes nothing: Status, the device file and the next start all keep
// the preset the data plane enforces.
func TestARulePresetRequestTheNodeNeverTookChangesNothing(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, true, deviceOpt{node: func(n *Node) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := n.SetRulePreset(ctx, "all-but-domestic"); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("got %v, want the context's error", err)
		}
		wantPreset(t, n, "space")
	}})
	b.connection(t, Connected)
	wantPreset(t, b.node, "space")
	if n, err := Prepare(b.node.cfg, Logs{}, testPlatform()); err != nil || n.Status().RulePreset != "space" {
		t.Fatalf("restart: %v", err)
	}
}

// A preset set while the device is disconnected is the one its next
// Connect enforces.
func TestARulePresetSetWhileDisconnectedIsTakenByTheConnect(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, false)
	ctx := context.Background()
	b.connection(t, Disconnected)
	if err := b.node.SetRulePreset(ctx, "all-but-domestic"); err != nil {
		t.Fatal(err)
	}
	wantPreset(t, b.node, "all-but-domestic")
	if err := b.node.Connect(ctx); err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatal(err)
	}
	if st := b.connection(t, Connected); st.DataPlane == nil {
		t.Fatalf("status %+v", st)
	}
	wantPreset(t, b.node, "all-but-domestic")
}

// errLayout is a layout that fails (tuning.tableFault, the route
// table's).
var errLayout = errors.New("laying out failed")

// A preset whose layout fails before the router takes it is stored and
// shown as not enforced while the router keeps the previous one; the
// caller hears it, the retry's Apply keeps failing while the router does,
// and once it can the Apply lays out the rules the engine kept.
func TestARulePresetWhoseLayoutFailsIsRetried(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	var failing atomic.Bool
	var tries atomic.Int32
	b := startDevice(t, s, reg, true, deviceOpt{tuning: func(tu *tuning) {
		tu.tableFault = func() error {
			if failing.Load() {
				tries.Add(1)
				return errLayout
			}
			return nil
		}
	}})
	b.connection(t, Connected)
	failing.Store(true)
	if err := b.node.SetRulePreset(context.Background(), "all-but-domestic"); !errors.Is(err, ErrPresetNotEnforced) || !errors.Is(err, errLayout) {
		t.Fatalf("got %v, want ErrPresetNotEnforced wrapping the layout's error", err)
	}
	notEnforced := func() {
		t.Helper()
		st := b.node.Status()
		if st.RulePreset != "all-but-domestic" || st.RulesEnforced || st.PresetUnavailable || st.RulesIncomplete || !st.Retrying ||
			!slices.Contains(st.Health().Problems, ProblemPresetNotEnforced) || slices.Contains(st.Health().Problems, ProblemPresetIncomplete) {
			t.Fatalf("status %+v, health %+v", st, st.Health())
		}
		if p := st.DataPlane.Rules.Preset.String(); p != "space" {
			t.Fatalf("the data plane enforces %q", p)
		}
	}
	notEnforced()
	eventually(t, func() bool { return tries.Load() >= 3 }) // retried
	notEnforced()
	failing.Store(false)
	eventually(t, func() bool { st := b.node.Status(); return st.RulesEnforced && !st.Retrying })
	wantPreset(t, b.node, "all-but-domestic")
	if st := b.node.Status(); st.RulesIncomplete || slices.Contains(st.Health().Problems, ProblemPresetNotEnforced) ||
		slices.Contains(st.Health().Problems, ProblemPresetIncomplete) {
		t.Fatalf("status %+v, health %+v", st, st.Health())
	}
}

// heldRouteTable is a device's route table whose Enforce can be held
// (each tells entered what Status shows then, and waits for release) or
// made to fail.
type heldRouteTable struct {
	node       *Node
	hold, fail atomic.Bool
	enforces   atomic.Int32
	entered    chan Status
	release    chan struct{}
}

func newHeldRouteTable() *heldRouteTable {
	return &heldRouteTable{entered: make(chan Status), release: make(chan struct{})}
}

func (h *heldRouteTable) opt() deviceOpt {
	return deviceOpt{
		prepare: func(_ *Config, p *Platform) {
			p.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) { return h, nil }
		},
		node: func(n *Node) { h.node = n },
	}
}

func (h *heldRouteTable) Enforce(context.Context, routetable.Want) error {
	if h.hold.Load() {
		h.entered <- h.node.Status()
		<-h.release
	}
	if h.fail.Load() {
		h.enforces.Add(1)
		return errLayout
	}
	return nil
}

func (h *heldRouteTable) Status() routetable.Status {
	if h.fail.Load() {
		return routetable.Status{Error: routetable.ErrorApply}
	}
	return routetable.Status{Enforced: true}
}

func (h *heldRouteTable) Close() error { return nil }

// A preset the router took, whose OS routing table then fails, is in
// place: the caller hears that the rest of its layout failed, not that
// the previous preset stays, and Status shows the preset enforced with
// what is missing, until the retry's Apply lays it out.
func TestARulePresetWhoseRouteTableFailsIsInPlace(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	h := newHeldRouteTable()
	b := startDevice(t, s, reg, true, h.opt())
	b.connection(t, Connected)
	h.fail.Store(true)
	err := b.node.SetRulePreset(context.Background(), "all-but-domestic")
	if !errors.Is(err, ErrPresetIncomplete) || !errors.Is(err, errLayout) || errors.Is(err, ErrPresetNotEnforced) {
		t.Fatalf("got %v, want ErrPresetIncomplete wrapping the route table's error", err)
	}
	inPlace := func() {
		t.Helper()
		st := b.node.Status()
		h := st.Health()
		if st.RulePreset != "all-but-domestic" || !st.RulesEnforced || !st.RulesIncomplete || !st.Retrying ||
			!slices.Contains(h.Problems, ProblemPresetIncomplete) || !slices.Contains(h.Problems, ProblemRouteTable) ||
			slices.Contains(h.Problems, ProblemPresetNotEnforced) {
			t.Fatalf("status %+v, health %+v", st, h)
		}
		if p := st.DataPlane.Rules.Preset.String(); p != "all-but-domestic" {
			t.Fatalf("the data plane enforces %q", p)
		}
	}
	inPlace()
	n := h.enforces.Load()
	eventually(t, func() bool { return h.enforces.Load() >= n+2 }) // retried
	inPlace()
	h.fail.Store(false)
	eventually(t, func() bool { st := b.node.Status(); return !st.RulesIncomplete && !st.Retrying })
	wantPreset(t, b.node, "all-but-domestic")
	if st := b.node.Status(); !st.RulesEnforced || slices.Contains(st.Health().Problems, ProblemPresetIncomplete) {
		t.Fatalf("status %+v, health %+v", st, st.Health())
	}
}

// A later preset laid out in full ends the retry a failed layout left:
// Status isn't retrying meanwhile.
func TestALaterRulePresetEndsTheFailedLayoutsRetry(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	var failing atomic.Bool
	b := startDevice(t, s, reg, true, deviceOpt{tuning: func(tu *tuning) {
		tu.retryAfter = time.Hour // the retry never comes in this test
		tu.tableFault = func() error {
			if failing.Load() {
				return errLayout
			}
			return nil
		}
	}})
	b.connection(t, Connected)
	ctx := context.Background()
	failing.Store(true)
	if err := b.node.SetRulePreset(ctx, "all-but-domestic"); !errors.Is(err, ErrPresetNotEnforced) {
		t.Fatalf("got %v, want ErrPresetNotEnforced", err)
	}
	if st := b.node.Status(); !st.Retrying {
		t.Fatalf("status %+v", st)
	}
	failing.Store(false)
	if err := b.node.SetRulePreset(ctx, "everything"); err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatal(err)
	}
	st := b.node.Status()
	if st.Retrying || !st.RulesEnforced || st.RulesIncomplete || st.Health().Level != HealthOK && slices.Contains(st.Health().Problems, ProblemRetrying) {
		t.Fatalf("status %+v, health %+v", st, st.Health())
	}
	wantPreset(t, b.node, "everything")
}

// blockDeviceFile makes storing the device file fail until the returned
// func is called: its temporary file's name is taken by a directory.
func blockDeviceFile(t *testing.T, dir string) func() {
	t.Helper()
	tmp := filepath.Join(dir, "."+DeviceFile+".new")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(tmp); err != nil {
			t.Fatal(err)
		}
	}
}

// A store that fails while the data plane runs changes nothing: the
// caller hears it, and Status, the device file and the data plane keep
// the preset (and the own rules) they had.
func TestARulePresetStoreThatFailsChangesNothing(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, true)
	b.connection(t, Connected)
	ctx := context.Background()
	if err := b.node.SetRulePreset(ctx, "all-but-domestic"); err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatal(err)
	}
	unblock := blockDeviceFile(t, b.node.cfg.StateDir)
	err := b.node.SetRulePreset(ctx, "everything")
	unblock()
	if err == nil || errors.Is(err, ErrPresetNotEnforced) || errors.Is(err, ErrPresetUnavailable) {
		t.Fatalf("got %v, want the store's error", err)
	}
	wantPreset(t, b.node, "all-but-domestic")
	if st := b.node.Status(); !st.RulesEnforced {
		t.Fatalf("status %+v", st)
	}
}

// A store that fails with no data plane running changes nothing either.
func TestARulePresetStoreThatFailsWhileStoppedChangesNothing(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	n, err := Prepare(testConfig(dir), Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	close(n.stopped)
	ctx := context.Background()
	if err := n.SetRulePreset(ctx, "everything"); err != nil {
		t.Fatal(err)
	}
	unblock := blockDeviceFile(t, dir)
	err = n.SetRulePreset(ctx, "all-but-domestic")
	unblock()
	if err == nil {
		t.Fatal("a store that failed was taken")
	}
	wantPreset(t, n, "everything")
}

// switchHeld has b switch to preset with every route table Enforce held,
// and returns what Status showed at each and what SetRulePreset said.
// SetRulePreset returning while one is held fails t.
func switchHeld(t *testing.T, b *deviceNode, h *heldRouteTable, preset string) ([]Status, error) {
	t.Helper()
	h.hold.Store(true)
	defer h.hold.Store(false)
	set := make(chan error, 1)
	go func() { set <- b.node.SetRulePreset(context.Background(), preset) }()
	var shown []Status
	for {
		select {
		case st := <-h.entered:
			shown = append(shown, st)
			select {
			case err := <-set:
				t.Errorf("SetRulePreset returned %v before the route table took it", err)
				h.release <- struct{}{}
				return shown, err
			default:
			}
			h.release <- struct{}{}
		case err := <-set:
			if len(shown) == 0 {
				t.Fatal("the switch never changed the route table")
			}
			return shown, err
		}
	}
}

// While the data plane switches presets, Status shows what the router
// enforces, enforced, at every step of the OS routing table's change
// (the engine unlocked): never the previous preset as not enforced once
// the router took the new one. SetRulePreset returns only once it is
// all laid out.
func TestARulePresetIsShownOnceTheRouterHasIt(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	h := newHeldRouteTable()
	b := startDevice(t, s, reg, true, h.opt())
	b.connection(t, Connected)
	shown, err := switchHeld(t, b, h, "all-but-domestic")
	for i, st := range shown {
		if p := st.DataPlane.Rules.Preset.String(); st.RulePreset != p || !st.RulesEnforced ||
			slices.Contains(st.Health().Problems, ProblemPresetNotEnforced) {
			t.Errorf("enforce %d: status shows %q (enforced %v, health %+v) while the router enforces %q", i, st.RulePreset, st.RulesEnforced, st.Health(), p)
		}
	}
	if err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatal(err)
	}
	wantPreset(t, b.node, "all-but-domestic")
}

// A switch the router took isn't shown incomplete for an earlier preset's
// failed layout while its own is laid out, and its success ends that.
func TestARulePresetSwitchIsntShownWithAnEarlierFailedLayout(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	h := newHeldRouteTable()
	opt := h.opt()
	opt.tuning = func(tu *tuning) { tu.retryAfter = time.Hour } // only the switch enforces
	b := startDevice(t, s, reg, true, opt)
	b.connection(t, Connected)
	h.fail.Store(true)
	if err := b.node.SetRulePreset(context.Background(), "all-but-domestic"); !errors.Is(err, ErrPresetIncomplete) {
		t.Fatalf("got %v, want ErrPresetIncomplete", err)
	}
	h.fail.Store(false)
	shown, err := switchHeld(t, b, h, "everything")
	for i, st := range shown {
		if st.RulePreset == "everything" && (st.RulesIncomplete || slices.Contains(st.Health().Problems, ProblemPresetIncomplete)) {
			t.Errorf("enforce %d: the switch shown incomplete: status %+v, health %+v", i, st, st.Health())
		}
	}
	if err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatal(err)
	}
	wantPreset(t, b.node, "everything")
	if st := b.node.Status(); st.RulesIncomplete || st.Retrying {
		t.Fatalf("status %+v", st)
	}
}

// A caller whose ctx ends after the node took its request hears what
// happened, not its ctx's error.
func TestARulePresetCallerThatGivesUpAfterTheTakeHearsTheOutcome(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	h := newHeldRouteTable()
	b := startDevice(t, s, reg, true, h.opt())
	b.connection(t, Connected)
	h.hold.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	set := make(chan error, 1)
	go func() { set <- b.node.SetRulePreset(ctx, "all-but-domestic") }()
	<-h.entered
	cancel()
	// Time for a caller that wrongly waits on its ctx to see it end
	// while the reply can't have come yet.
	time.Sleep(100 * time.Millisecond)
	h.hold.Store(false)
	h.release <- struct{}{}
	if err := <-set; err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatalf("got %v, want the outcome", err)
	}
	wantPreset(t, b.node, "all-but-domestic")
}

// A second SetRulePreset waits for the first only as long as its ctx
// lets it, and changes nothing.
func TestASecondRulePresetCallGivesUpOnItsCtx(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	h := newHeldRouteTable()
	b := startDevice(t, s, reg, true, h.opt())
	b.connection(t, Connected)
	h.hold.Store(true)
	first := make(chan error, 1)
	go func() { first <- b.node.SetRulePreset(context.Background(), "all-but-domestic") }()
	<-h.entered
	second := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		second <- b.node.SetRulePreset(ctx, "everything")
	}()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("second: got %v, want its ctx's error", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the second call outwaited its ctx")
	}
	h.hold.Store(false)
	h.release <- struct{}{}
	if err := <-first; err != nil && !errors.Is(err, ErrPresetUnavailable) {
		t.Fatal(err)
	}
	wantPreset(t, b.node, "all-but-domestic")
}

// wantPreset fails t unless Status, the device file and, while it runs,
// the data plane all say preset.
func wantPreset(t *testing.T, n *Node, preset string) {
	t.Helper()
	st := n.Status()
	if st.RulePreset != preset {
		t.Errorf("status shows %q, want %q", st.RulePreset, preset)
	}
	if st.DataPlane != nil && st.DataPlane.Rules.Preset.String() != preset {
		t.Errorf("the data plane enforces %q, want %q", st.DataPlane.Rules.Preset, preset)
	}
	stored := "space"
	data, err := os.ReadFile(filepath.Join(n.cfg.StateDir, DeviceFile))
	switch {
	case err == nil:
		d, err := parseDeviceSettings(data)
		if err != nil {
			t.Fatal(err)
		}
		stored = d.Rules.Preset.String()
	case !errors.Is(err, os.ErrNotExist):
		t.Fatal(err)
	}
	if stored != preset {
		t.Errorf("the device file holds %q, want %q", stored, preset)
	}
}

// The device's own rules stay when the preset changes.
func TestTheDevicesOwnRulesAreKept(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, DeviceFile), []byte(`{"rules": ["cidr:192.0.2.0/24 -> direct"]}`), 0o600)
	n, err := Prepare(testConfig(dir), Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if len(n.device.Rules.Rules) != 1 || n.Status().RulePreset != "space" {
		t.Fatalf("read %+v", n.device)
	}
	close(n.stopped) // not running: the choice is only stored
	if err := n.SetRulePreset(context.Background(), "all-but-domestic"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, DeviceFile))
	if err != nil || !strings.Contains(string(got), `"rule_preset": "all-but-domestic"`) || !strings.Contains(string(got), `"cidr:192.0.2.0/24 -> direct"`) {
		t.Fatalf("file %q, %v", got, err)
	}
}

// A local rules file that can't be read or parsed never reads as none:
// the node refuses to start.
func TestABadLocalRulesFileFailsClosed(t *testing.T) {
	s := newTestSpace(t)
	for name, tc := range map[string]struct {
		data string
		perm os.FileMode
	}{
		"unknown preset":  {"preset sometimes\n", 0o644},
		"two presets":     {"preset everything\npreset space\n", 0o644},
		"writable by all": {"preset everything\n", 0o666},
	} {
		dir := s.stateDir(t, s.b, 1)
		writeFile(t, filepath.Join(dir, LocalRulesFile), []byte(tc.data), tc.perm)
		if _, err := Prepare(testConfig(dir), Logs{}, testPlatform()); err == nil || !strings.Contains(err.Error(), LocalRulesFile) {
			if runtime.GOOS != "windows" || name != "writable by all" {
				t.Errorf("%s: got %v", name, err)
			}
		}
	}
}

func TestADeviceStartingDisconnectedNeedsTheAPI(t *testing.T) {
	s := newTestSpace(t)
	cfg := testConfig(s.stateDir(t, s.b, 1))
	cfg.Connect, cfg.APISocket = false, ""
	if _, err := Prepare(cfg, Logs{}, testPlatform()); err == nil || !strings.Contains(err.Error(), "local API") {
		t.Fatalf("got %v", err)
	}
	cfg.Mode = ModeDevice
	if err := cfg.Validate(); err == nil {
		t.Fatal("Check took it")
	}
	cfg.APISocket = "/run/x/api.sock"
	if _, err := Prepare(cfg, Logs{}, testPlatform()); err != nil {
		t.Fatal(err)
	}
}

// hostTouches counts what a node does to its host's network through the
// platform: TUNs, configurators, route tables, resolver configuration
// and the clean-ups of a crashed run's.
type hostTouches struct{ n atomic.Int32 }

func (h *hostTouches) count(plat *Platform) {
	tun, cfg, table := plat.NewTUN, plat.NewConfigurator, plat.NewRouteTable
	plat.NewTUN = func(name string, mtu int) (wgtun.Device, error) { h.n.Add(1); return tun(name, mtu) }
	plat.NewConfigurator = func(o netcfg.Owner) (netcfg.Configurator, error) { h.n.Add(1); return cfg(o) }
	plat.NewRouteTable = func(l *slog.Logger, g routetable.Guard) (RouteEnforcer, error) { h.n.Add(1); return table(l, g) }
	plat.ClearConfig = func(netcfg.Owner) error { h.n.Add(1); return nil }
	plat.ClearRouteTable = func(routetable.Guard) error { h.n.Add(1); return nil }
	plat.SetSystemDNS = func(dns.SystemConfig) (dns.System, error) { h.n.Add(1); return nil, errors.New("not here") }
	plat.RestoreDNS = func() error { h.n.Add(1); return nil }
}

// With no mode set anywhere (environment, node file), a node whose map
// makes it an exit (and a server devices link to) runs in device mode,
// which runs no server's section (PRD A4): it opens no listener, so the
// device that links to it gets no link and nothing is relayed or
// forwarded, and it leaves the host alone: no TUN, route, resolver or
// clean-up. Its status and log say why and what to set.
func TestAServerWithNoModeSetRunsNothing(t *testing.T) {
	unsetTHINKPOL(t)
	s := newTestSpace(t)
	net, reg := memoryRegistry(t)
	var host hostTouches
	a := startDevice(t, s, reg, true, deviceOpt{prepare: func(c *Config, plat *Platform) {
		dir := s.stateDir(t, s.a, 1)
		writeFile(t, filepath.Join(dir, MapFileName), s.buildEditing(t, 1, s.a, func(sec *netmap.Section) { sec.Node.AllowEgress = true }), 0o644)
		loaded, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		loaded.StateDir = dir
		if err := ApplyNodeFile(&loaded, nil); err != nil {
			t.Fatal(err)
		}
		c.StateDir, c.Mode = dir, loaded.Mode
		host.count(plat)
	}})
	var st Status
	eventually(t, func() bool { st = a.node.Status(); return st.ModeMismatch })
	if h := st.Health(); st.Mode != ModeDevice || st.DataPlane != nil || st.Listeners != 0 || st.Removed ||
		h.Level != HealthDown || !slices.Equal(h.Problems, []Problem{ProblemModeMismatch}) {
		t.Fatalf("status %+v, health %+v", st, h)
	}
	eventually(t, func() bool { return strings.Contains(a.log.String(), `in node.json (or -mode server) and restart`) })
	if _, err := net.Dial(context.Background(), s.listen.String(), transport.DialConfig{Credential: s.secret}); err == nil ||
		!strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("its listener: %v", err)
	}

	b := startNode(t, reg, s.b, s.verified(t, 1))
	eventually(t, func() bool { return slices.Contains(b.status().Health().Problems, ProblemNoLinkUp) })
	if dp := b.status().DataPlane; dp == nil || len(dp.Neighbors) != 1 || dp.Neighbors[0].Up {
		t.Fatalf("the device's links: %+v", dp)
	}
	if n := host.n.Load(); n != 0 || a.tuns.Load() != 0 {
		t.Fatalf("the host was touched %d times, %d TUNs", n, a.tuns.Load())
	}
}

// A device the map makes a server stops its data plane, as on a removal,
// says so (mode_mismatch), and starts again once the map makes it a
// device again.
func TestADeviceTheMapMakesAServerStops(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	b := startDevice(t, s, reg, true)
	b.connection(t, Connected)
	b.maps <- s.buildBoth(t, 2, func(a, b *netmap.Section) { b.Node.Kind, a.Inbound[0].PeerKind = netmap.NodeServer, netmap.NodeServer })
	var st Status
	eventually(t, func() bool { st = b.node.Status(); return st.ModeMismatch })
	if h := st.Health(); st.DataPlane != nil || st.Listeners != 0 || st.Connection != Connecting || st.MapVersion != 2 ||
		!slices.Equal(h.Problems, []Problem{ProblemModeMismatch}) {
		t.Fatalf("status %+v, health %+v", st, h)
	}
	if !strings.Contains(b.log.String(), `in node.json (or -mode server) and restart`) {
		t.Fatalf("log:\n%s", b.log)
	}
	b.maps <- s.build(t, 3)
	st = b.connection(t, Connected)
	if st.ModeMismatch || st.DataPlane == nil || slices.Contains(st.Health().Problems, ProblemModeMismatch) {
		t.Fatalf("status %+v", st)
	}
}

// A device-mode node that starts on a map making it a server runs once a
// map makes it a device, and only then puts back what a crashed run left
// on the host, once: the resolver configuration, and the routing when it
// starts disconnected (connecting takes that over).
func TestADeviceStartedAsAServerRunsOnceTheMapMakesItADevice(t *testing.T) {
	for _, tc := range []struct {
		connect             bool
		want                Connection
		restored, routesCut int32
	}{
		{true, Connected, 1, 0},
		{false, Disconnected, 1, 1},
	} {
		t.Run(fmt.Sprint("connect=", tc.connect), func(t *testing.T) {
			s := newTestSpace(t)
			_, reg := memoryRegistry(t)
			startNode(t, reg, s.a, s.verified(t, 1))
			var restored, overlayCut, tableCut atomic.Int32
			b := startDevice(t, s, reg, tc.connect, deviceOpt{prepare: func(c *Config, plat *Platform) {
				writeFile(t, filepath.Join(c.StateDir, MapFileName), s.buildBoth(t, 1, func(a, b *netmap.Section) {
					b.Node.Kind, a.Inbound[0].PeerKind = netmap.NodeServer, netmap.NodeServer
				}), 0o644)
				plat.RestoreDNS = func() error { restored.Add(1); return nil }
				plat.ClearConfig = func(o netcfg.Owner) error {
					if o == netcfg.OwnerOverlay {
						overlayCut.Add(1)
					}
					return nil
				}
				plat.ClearRouteTable = func(routetable.Guard) error { tableCut.Add(1); return nil }
			}})
			eventually(t, func() bool { return b.node.Status().ModeMismatch })
			if n := restored.Load() + overlayCut.Load() + tableCut.Load(); n != 0 {
				t.Fatalf("the host was touched %d times while mismatched", n)
			}

			b.maps <- s.build(t, 2)
			var st Status
			eventually(t, func() bool { st = b.node.Status(); return st.MapVersion == 2 && st.Connection == tc.want })
			if st.ModeMismatch || slices.Contains(st.Health().Problems, ProblemModeMismatch) {
				t.Fatalf("status %+v", st)
			}
			if tc.connect && st.DataPlane == nil {
				t.Fatalf("no data plane: %+v", st)
			}
			if r, o, rt := restored.Load(), overlayCut.Load(), tableCut.Load(); r != tc.restored || o != tc.routesCut || rt != tc.routesCut {
				t.Fatalf("resolver restored %d times, overlay routes cleared %d, route table %d; want %d, %d, %d",
					r, o, rt, tc.restored, tc.routesCut, tc.routesCut)
			}
		})
	}
}

// A device that starts disconnected (after a crash: `thinkpol up
// -connect=false`) clears what the crashed run left for both of the data
// plane's owners on the host: the route table's and the overlay's, whose
// routes went with the utun but stayed in its record on macOS.
func TestAStartWhileDisconnectedClearsACrashedRunsRoutes(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	cleared := make(chan netcfg.Owner, 4)
	startDevice(t, s, reg, false, deviceOpt{prepare: func(_ *Config, p *Platform) {
		p.ClearConfig = func(o netcfg.Owner) error { cleared <- o; return nil }
		p.ClearRouteTable = func(routetable.Guard) error { cleared <- netcfg.OwnerRouteTable; return nil }
	}})
	for _, want := range []netcfg.Owner{netcfg.OwnerRouteTable, netcfg.OwnerOverlay} {
		select {
		case got := <-cleared:
			if got != want {
				t.Fatalf("cleared %v, want %v", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a disconnected start cleared nothing")
		}
	}
}

// A device whose only exit refuses its dial says no_link_up at once, long
// before DeadAfter: a failed dial is not a dial still waiting for an
// answer. The link coming up clears it.
func TestADialThatFailedIsNoLinkUp(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	const deadAfter = time.Minute
	b := startDevice(t, s, reg, true, deviceOpt{tuning: func(t *tuning) { t.path.DeadAfter = deadAfter }})
	b.connection(t, Connected)
	var h Health
	eventually(t, func() bool { h = b.node.Status().Health(); return slices.Contains(h.Problems, ProblemNoLinkUp) })
	if h.Level != HealthDown {
		t.Fatalf("a dial that failed: health %+v, want down", h)
	}

	startNode(t, reg, s.a, s.verified(t, 1))
	eventually(t, func() bool { h = b.node.Status().Health(); return h.Level == HealthOK })
}

// A device with two exits, one linked and one whose dials fail, is
// degraded with neighbor_down, not down: the other exit still answers.
func TestADialThatFailedBesideALinkIsNeighborDown(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	other := netmap.NodeID{0, 0, 0, 0, 0, 0, 0, 3}
	env := s.buildEditing(t, 1, s.b, func(sec *netmap.Section) {
		sec.Links = append(sec.Links, netmap.Link{Peer: other, Endpoints: []netmap.Endpoint{{
			Transport: memory.Name, Address: netip.MustParseAddrPort("192.0.2.3:4500"), Credential: s.secret}}})
	})
	b := startDevice(t, s, reg, true, deviceOpt{prepare: func(c *Config, _ *Platform) {
		writeFile(t, filepath.Join(c.StateDir, MapFileName), env, 0o644)
	}})
	b.connection(t, Connected)
	var st Status
	eventually(t, func() bool {
		st = b.node.Status()
		return slices.Contains(st.Health().Problems, ProblemNeighborDown)
	})
	if h := st.Health(); h.Level != HealthDegraded || slices.Contains(h.Problems, ProblemNoLinkUp) {
		t.Fatalf("one exit up, one never linked: health %+v, want degraded, neighbor_down", h)
	}
	up, down := 0, 0
	for _, n := range st.DataPlane.Neighbors {
		switch {
		case n.Up:
			up++
		case n.Node == path.NodeID(other) && len(n.Links) == 0:
			down++
		}
	}
	if up != 1 || down != 1 {
		t.Fatalf("neighbors %+v, want the linked exit up and the other listed down with no links", st.DataPlane.Neighbors)
	}
}

// Exits are graded by their WireGuard handshakes: a default exit
// unanswered past the deadline is down, any other exit unanswered is
// degraded, and the deadline runs only while the exit's first hop is up
// and an initiation went out since it came up. The default exits are what
// carries each family's background route.
// A chain has one exit (netmap.Chain), so "none of the default chain's
// exits answers" is that exit unanswered, whatever the others do.
func TestExitsAreGradedByTheirHandshakes(t *testing.T) {
	now := time.Now()
	const deadline = dataplane.ExitHandshakeDeadline
	var nl, de, relay, dev netmap.NodeID
	nl[0], de[0], relay[0], dev[0] = 1, 2, 3, 4
	upFor := func(n netmap.NodeID, d time.Duration) path.NeighborStatus {
		return path.NeighborStatus{Node: path.NodeID(n), Up: true, UpFor: d}
	}
	downNeighbor := path.NeighborStatus{Node: path.NodeID(nl)}
	pendingFor := func(n, hop netmap.NodeID, d time.Duration) dataplane.PeerStatus {
		return dataplane.PeerStatus{ID: n, Exit: true, FirstHop: hop, HandshakePendingSince: now.Add(-d), LastInitiation: now, LastHandshake: now.Add(-time.Minute)}
	}
	// WireGuard gave up retrying d ago, without traffic since.
	gaveUp := func(n netmap.NodeID, d time.Duration) dataplane.PeerStatus {
		p := pendingFor(n, n, time.Hour)
		p.LastInitiation = now.Add(-d)
		return p
	}
	dead := func(n netmap.NodeID) dataplane.PeerStatus { return pendingFor(n, n, deadline) }
	live := func(n netmap.NodeID) dataplane.PeerStatus {
		return dataplane.PeerStatus{ID: n, Exit: true, FirstHop: n, LastHandshake: now.Add(-time.Second)}
	}
	idle := func(n netmap.NodeID) dataplane.PeerStatus {
		return dataplane.PeerStatus{ID: n, Exit: true, FirstHop: n, LastHandshake: now.Add(-time.Hour)}
	}
	both := []path.NeighborStatus{upFor(nl, time.Hour), upFor(de, time.Hour)}
	exitDown := Health{HealthDown, []Problem{ProblemExitNoHandshake}}
	exitDegraded := Health{HealthDegraded, []Problem{ProblemExitNoHandshake}}
	defNL, defDE := [2]netmap.NodeID{nl, nl}, [2]netmap.NodeID{de, de}
	for _, tc := range []struct {
		name      string
		neighbors []path.NeighborStatus
		peers     []dataplane.PeerStatus
		def       [2]netmap.NodeID // the default exits (IPv4, IPv6); zero: direct
		want      Health
	}{
		{"default direct, a chain's exit dead", both, []dataplane.PeerStatus{dead(nl), live(de)}, [2]netmap.NodeID{}, exitDegraded},
		{"default nl dead, de idle", both, []dataplane.PeerStatus{dead(nl), idle(de)}, defNL, exitDown},
		{"default nl dead, de live", both, []dataplane.PeerStatus{dead(nl), live(de)}, defNL, exitDown},
		{"default nl live, de dead", both, []dataplane.PeerStatus{live(nl), dead(de)}, defNL, exitDegraded},
		{"all live under steady traffic", both, []dataplane.PeerStatus{live(nl), live(de)}, defNL, Health{}},
		{"all idle", both, []dataplane.PeerStatus{idle(nl), idle(de)}, defNL, Health{}},
		{"default nl pending for less than the deadline", both, []dataplane.PeerStatus{pendingFor(nl, nl, deadline-time.Second)}, defNL, Health{}},
		{"default nl dead behind a relay", []path.NeighborStatus{upFor(relay, time.Hour)}, []dataplane.PeerStatus{pendingFor(nl, relay, time.Hour)}, defNL, exitDown},
		{"default nl's first hop down: the neighbor's problem only", []path.NeighborStatus{downNeighbor},
			[]dataplane.PeerStatus{pendingFor(nl, netmap.NodeID{}, time.Hour)}, defNL, Health{HealthDown, []Problem{ProblemNoLinkUp}}},
		{"default nl's first hop down, its last hop kept", []path.NeighborStatus{downNeighbor, upFor(de, time.Hour)},
			[]dataplane.PeerStatus{dead(nl), live(de)}, defNL, Health{HealthDegraded, []Problem{ProblemNeighborDown}}},
		{"default nl's first hop back for less than the deadline", []path.NeighborStatus{upFor(nl, deadline-time.Second)},
			[]dataplane.PeerStatus{pendingFor(nl, nl, time.Hour)}, defNL, Health{}},
		{"default nl's first hop back for the deadline", []path.NeighborStatus{upFor(nl, deadline)},
			[]dataplane.PeerStatus{pendingFor(nl, nl, time.Hour)}, defNL, exitDown},
		{"default nl's first hop back for the deadline, no initiation since", []path.NeighborStatus{upFor(nl, time.Hour)},
			[]dataplane.PeerStatus{gaveUp(nl, time.Hour+time.Second)}, defNL, Health{}},
		{"default nl given up on while its first hop stayed up", []path.NeighborStatus{upFor(nl, time.Hour)},
			[]dataplane.PeerStatus{gaveUp(nl, time.Hour-time.Second)}, defNL, exitDown},
		{"both families' background through de, de dead, nl idle", both, []dataplane.PeerStatus{idle(nl), dead(de)}, defDE, exitDown},
		{"IPv6's background through de, de dead, nl live", both, []dataplane.PeerStatus{live(nl), dead(de)}, [2]netmap.NodeID{nl, de}, exitDown},
		{"a device peer pending for long", []path.NeighborStatus{upFor(dev, time.Hour)},
			[]dataplane.PeerStatus{{ID: dev, FirstHop: dev, HandshakePendingSince: now.Add(-time.Hour)}}, defNL, Health{}},
	} {
		dp := &dataplane.Status{Neighbors: tc.neighbors, Peers: tc.peers, Rules: dataplane.RuleStatus{DefaultExits: tc.def}}
		s := Status{Connection: Connected, DataPlane: dp}
		s.ExitsUnanswered, s.DefaultExitUnanswered = exitHandshakes(dp, now, deadline)
		if got := s.Health(); got.Level != tc.want.Level || !slices.Equal(got.Problems, tc.want.Problems) {
			t.Errorf("%s: health %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// A device whose only exit is linked but whose WireGuard doesn't answer
// (the exit's map doesn't list the device) says exit_no_handshake once
// traffic to the internet waits past the deadline; the exit taking the
// device into its map, and the handshake that follows, clear it.
func TestAnExitThatNeverHandshakesIsExitNoHandshake(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	s.deviceChains, s.serverEgress = []netmap.Chain{{Name: "nl", Exit: s.a.ID}}, true
	r, err := netmap.ParseRule("default -> chain:nl")
	if err != nil {
		t.Fatal(err)
	}
	s.deviceRules = []netmap.Rule{r}
	deaf, err := netmap.Verify(s.buildEditing(t, 1, s.a, func(sec *netmap.Section) { sec.Peers = nil }), s.trust())
	if err != nil {
		t.Fatal(err)
	}
	a := startNode(t, reg, s.a, deaf)
	b := startDevice(t, s, reg, true, deviceOpt{tuning: func(t *tuning) { t.exitDeadline = time.Second }})
	b.connection(t, Connected)

	b4, _ := overlay(2)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for seq := uint16(1); ; seq++ {
			if ch := b.ch.Load(); ch != nil {
				select {
				case ch.Outbound <- packettest.Echo(b4, netip.MustParseAddr("192.0.2.80"), 1, seq, nil):
				case <-stop:
					return
				}
			}
			select {
			case <-time.After(100 * time.Millisecond):
			case <-stop:
				return
			}
		}
	}()
	var st Status
	eventually(t, func() bool {
		st = b.node.Status()
		return slices.Contains(st.Health().Problems, ProblemExitNoHandshake)
	})
	if h := st.Health(); h.Level != HealthDown || slices.Contains(h.Problems, ProblemNoLinkUp) || st.ExitsUnanswered != 1 {
		t.Fatalf("the exit linked, its WireGuard deaf: health %+v, status %+v", h, st)
	}

	a.maps <- s.build(t, 2)
	// WireGuard initiates again RekeyTimeout (5 s) after the last one. Ok
	// alone isn't the exit answering: a busy machine can hold fastPaths'
	// probes past their second, and once the link re-dials an initiation
	// sent before it isn't graded, so health reads ok with none answered.
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		st = b.node.Status()
		if exitHandshook(st) && st.Health().Level == HealthOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still %+v after the exit took the device in: %+v", st.Health(), peersOf(st))
		}
	}
	// A healthy exit under steady traffic isn't flagged over several
	// deadlines. A link re-dialed on a busy machine raises no_link_up or
	// neighbor_down, which have their own tests; anything else, or the
	// data plane going away, is a regression.
	for until := time.Now().Add(4 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
		st = b.node.Status()
		h := st.Health()
		unexpected := slices.ContainsFunc(h.Problems, func(p Problem) bool {
			return p != ProblemNoLinkUp && p != ProblemNeighborDown
		})
		if st.Connection != Connected || st.DataPlane == nil || unexpected || st.ExitsUnanswered != 0 {
			t.Fatalf("the exit answering under steady traffic: connection %v, %+v, peers %+v", st.Connection, h, peersOf(st))
		}
	}
}

// peersOf returns st's data plane peers, none without a data plane.
func peersOf(st Status) []dataplane.PeerStatus {
	if st.DataPlane == nil {
		return nil
	}
	return st.DataPlane.Peers
}

// exitHandshook reports whether st's data plane has an exit peer and has
// completed a handshake with each, none pending since.
func exitHandshook(st Status) bool {
	if st.DataPlane == nil {
		return false
	}
	exits := 0
	for _, p := range st.DataPlane.Peers {
		if p.Exit {
			if p.LastHandshake.IsZero() || !p.HandshakePendingSince.IsZero() {
				return false
			}
			exits++
		}
	}
	return exits > 0
}
