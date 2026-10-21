package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
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
// before it runs, dataPlane sets its data plane's private test fields and
// RouteTable (off by default: virtual TUNs leave the host's routing
// alone) before it runs.
type deviceOpt struct {
	prepare   func(*Config, *Platform)
	node      func(*Node)
	dataPlane func(*DataPlane)
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
	rn.status = n.Status
	d := &deviceNode{runningNode: rn, node: n, failTUN: failTUN, events: newHeardEvents(t)}
	n.Subscribe(d.events.add)
	for _, o := range opts {
		if o.node != nil {
			o.node(n)
		}
	}
	n.tweak = func(dp *DataPlane) {
		dp.tuning = tuning{path: fastPaths, retryAfter: testRetry}
		dp.RouteTable = false // virtual TUNs: the host's routing stays as it is
		for _, o := range opts {
			if o.dataPlane != nil {
				o.dataPlane(dp)
			}
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
	if h := st.Health(); h.Level != HealthDown || !slices.Equal(h.Problems, []string{ProblemDisconnected}) {
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
	if st := b.node.Status(); !st.Removed || st.Mode != ModeAuto {
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
		dataPlane: func(dp *DataPlane) { dp.RouteTable = true },
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
		dataPlane: func(dp *DataPlane) { dp.RouteTable = true },
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
		dataPlane: func(dp *DataPlane) { dp.tuning.dnsPort = 5353 },
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
	n, err := Prepare(testConfig(s.stateDir(t, s.a, 1)), Logs{}, testPlatform())
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

func TestWorkerLastExitInStatus(t *testing.T) {
	const reason = "start: no such file"
	space := netmap.SpaceID{0x01}
	st := (&report{
		mode:    ModeServer,
		workers: stubWorkerReporter{workers: []supervisor.WorkerInfo{{Space: space, Ready: false, Starts: 1, LastExit: reason}}},
	}).status()
	if len(st.Workers) != 1 || st.Workers[0].LastExit != reason {
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
		{"disconnected", Status{Connection: Disconnected}, Health{HealthDown, []string{ProblemDisconnected}}},
		{"starting", Status{Connection: Connecting}, Health{HealthDown, []string{ProblemStarting}}},
		{"retrying", Status{Connection: Connecting, Retrying: true}, Health{HealthDown, []string{ProblemRetrying}}},
		{"removed", Status{Connection: Connecting, Removed: true}, Health{HealthDown, []string{ProblemRemoved}}},
		{"no link up", Status{Connection: Connected, DataPlane: &dataplane.Status{Neighbors: []path.NeighborStatus{down, down}}},
			Health{HealthDown, []string{ProblemNoLinkUp}}},
		{"one down", Status{Connection: Connected, DataPlane: &dataplane.Status{Neighbors: []path.NeighborStatus{up, down},
			LastApplyError: dataplane.StepRouter, Skipped: []dataplane.Skip{{}}}},
			Health{HealthDegraded, []string{ProblemApplyFailed, ProblemNeighborDown, ProblemSkipped}}},
		{"route table not enforced", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Error: routetable.ErrorReapply, Routes: 9}}},
			Health{HealthDown, []string{ProblemRouteTable}}},
		{"rules ahead of the route table", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, RulesAhead: 2}}},
			Health{HealthDegraded, []string{ProblemRulesAhead}}},
		{"overlay addresses taken around the route table", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, OverlayAhead: 1}}},
			Health{HealthDown, []string{ProblemOverlayRoutesAhead}}},
		{"leak guard failing, routes in place", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, GuardError: routetable.ErrorGuard}}},
			Health{HealthDegraded, []string{ProblemGuard}}},
		{"no nf_tables: connected, a loud warning", Status{Connection: Connected, DataPlane: &dataplane.Status{
			RouteTable: dataplane.RouteTableStatus{Enforced: true, Routes: 9, GuardError: routetable.ErrorGuardUnsupported}}},
			Health{HealthDegraded, []string{ProblemGuardUnsupported}}},
		{"server", Status{Connection: Serving, Workers: []WorkerStatus{{Ready: true, Starts: 1}}}, Health{}},
		{"server worker down", Status{Connection: Serving, Workers: []WorkerStatus{{Ready: true, Starts: 3}, {}},
			PublicListeners: []PublicListenerStatus{{Rejected: 1}}},
			Health{HealthDown, []string{ProblemWorkerDown, ProblemWorkerRestarts, ProblemLinksRejected}}},
		{"server retrying", Status{Connection: Serving, Retrying: true}, Health{HealthDegraded, []string{ProblemRetrying}}},
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
	file := filepath.Join(dir, LocalRulesFile)
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
	if got, err := os.ReadFile(file); err != nil || string(got) != "preset everything\n" {
		t.Fatalf("file %q, %v", got, err)
	}
	if fi, _ := os.Lstat(file); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	st = b.node.Status()
	if st.RulePreset != "everything" || !st.PresetUnavailable || !slices.Contains(st.Health().Problems, ProblemPresetUnavailable) {
		t.Fatalf("status %+v", st)
	}
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
	// A server has no rules of its own.
	if a, err := Prepare(testConfig(s.stateDir(t, s.a, 1)), Logs{}, testPlatform()); err != nil || !errors.Is(a.SetRulePreset(ctx, "everything"), ErrServerMode) {
		t.Fatalf("server: %v", err)
	}
}

// The device's own rules stay when the preset changes.
func TestTheDevicesOwnRulesAreKept(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, LocalRulesFile), []byte("# mine\ncidr:192.0.2.0/24 -> direct\n"), 0o644)
	n, err := Prepare(testConfig(dir), Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if len(n.local.Rules) != 1 || n.Status().RulePreset != "space" {
		t.Fatalf("read %+v", n.local)
	}
	close(n.stopped) // not running: the choice is only stored
	if err := n.SetRulePreset(context.Background(), "all-but-domestic"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, LocalRulesFile))
	if err != nil || !strings.HasPrefix(string(got), "preset all-but-domestic\n") || !strings.Contains(string(got), "192.0.2.0/24") {
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
