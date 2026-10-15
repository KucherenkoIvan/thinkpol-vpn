package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
}

// startDevice starts device b; each of opts is called with its config
// (and a nil DataPlane) before it is prepared, then with its DataPlane
// (and a nil Config) before it runs.
func startDevice(t *testing.T, s *testSpace, reg *transport.Registry, connect bool, opts ...func(*Config, *DataPlane)) *deviceNode {
	t.Helper()
	cfg := testConfig(s.stateDir(t, s.b, 1))
	cfg.Connect = connect
	for _, o := range opts {
		o(&cfg, nil)
	}
	rn := newRunningNode()
	logs, err := NewLogs("debug", rn.log)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Prepare(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	d := &deviceNode{runningNode: rn, node: n, failTUN: make(chan struct{}, 1)}
	n.tweak = func(dp *DataPlane) {
		virtual := rn.dataPlane(reg, s.b, n.state.Map)
		dp.path, dp.retryAfter = virtual.path, virtual.retryAfter
		dp.RouteTable = false // virtual TUNs: the host's routing stays as it is
		dp.newTUN = func(name string) (wgtun.Device, netcfg.Configurator, error) {
			select {
			case <-d.failTUN:
				return nil, nil, errors.New("no TUN today")
			default:
			}
			return virtual.newTUN(name)
		}
		for _, o := range opts {
			o(nil, dp)
		}
	}
	go func() { rn.done <- n.run(rn.ctx, reg, rn.maps) }()
	t.Cleanup(func() {
		rn.stop()
		select {
		case <-rn.done:
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
	b.waitLog(t, `msg="map applied" .*version=3`)

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

	// Stopped, it says so.
	b.stop()
	if err := <-b.done; err != nil {
		t.Fatal(err)
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
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
	cfg := testConfig(dir)
	cfg.Connect = false
	rn := newRunningNode()
	logs, err := NewLogs("info", rn.log)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Prepare(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	n.tweak = func(dp *DataPlane) {
		virtual := rn.dataPlane(reg, s.b, n.state.Map)
		dp.newTUN, dp.path, dp.retryAfter = virtual.newTUN, virtual.path, virtual.retryAfter
		dp.RouteTable = false
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- n.run(ctx, reg, rn.maps) }()
	if st := n.Status(); !st.Removed || st.Mode != ModeAuto {
		t.Fatalf("status %+v", st)
	}
	if err := n.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if st := n.Status(); st.Connection != Connecting {
		t.Fatalf("status %+v", st)
	}
	rn.maps <- s.build(t, 2)
	eventually(t, func() bool { return n.Status().Connection == Connected })
	if st := n.Status(); st.Mode != ModeDevice || st.Removed || st.MapVersion != 2 {
		t.Fatalf("status %+v", st)
	}
	b4, _ := overlay(2)
	a4, _ := overlay(1)
	rn.ping(t, b4, a4)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAServerRefusesConnect(t *testing.T) {
	s := newTestSpace(t)
	n, err := Prepare(testConfig(s.stateDir(t, s.a, 1)), Logs{})
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
	workers    []supervisor.WorkerInfo
	staleClock func() (uint64, uint64, time.Time)
}

func (s stubWorkerReporter) Workers() []supervisor.WorkerInfo   { return s.workers }
func (stubWorkerReporter) Listeners() []supervisor.ListenerInfo { return nil }
func (stubWorkerReporter) Egress() supervisor.EgressInfo        { return supervisor.EgressInfo{} }
func (s stubWorkerReporter) StaleClock() (uint64, uint64, time.Time) {
	if s.staleClock != nil {
		return s.staleClock()
	}
	return 0, 0, time.Time{}
}

func TestSupervisorStaleClockInStatus(t *testing.T) {
	seen := time.Now()
	st := (&report{
		mode: ModeServer,
		workers: stubWorkerReporter{
			staleClock: func() (uint64, uint64, time.Time) { return 9, 4, seen },
		},
	}).status()
	if st.StaleClock != 9 || st.StaleClockBurst != 4 || st.StaleClockSeen != seen {
		t.Fatalf("status %+v", st)
	}
}

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
		{"clock skew below threshold", Status{Connection: Connected, StaleClock: 2, StaleClockBurst: 2, StaleClockSeen: time.Now()}, Health{}},
		{"clock skew", Status{Connection: Connected, StaleClock: 3, StaleClockBurst: 3, StaleClockSeen: time.Now()},
			Health{HealthDegraded, []string{ProblemClockSkew}}},
		{"clock skew cleared", Status{Connection: Connected, StaleClock: 3, StaleClockBurst: 3, StaleClockSeen: time.Now().Add(-staleClockWindow - time.Second)}, Health{}},
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
	n, err := Prepare(b.node.cfg, Logs{})
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
	if a, err := Prepare(testConfig(s.stateDir(t, s.a, 1)), Logs{}); err != nil || !errors.Is(a.SetRulePreset(ctx, "everything"), ErrServerMode) {
		t.Fatalf("server: %v", err)
	}
}

// The device's own rules stay when the preset changes.
func TestTheDevicesOwnRulesAreKept(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, LocalRulesFile), []byte("# mine\ncidr:192.0.2.0/24 -> direct\n"), 0o644)
	n, err := Prepare(testConfig(dir), Logs{})
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
		if _, err := Prepare(testConfig(dir), Logs{}); err == nil || !strings.Contains(err.Error(), LocalRulesFile) {
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
	if _, err := Prepare(cfg, Logs{}); err == nil || !strings.Contains(err.Error(), "local API") {
		t.Fatalf("got %v", err)
	}
	cfg.Mode = ModeDevice
	if err := cfg.Validate(); err == nil {
		t.Fatal("Check took it")
	}
	cfg.APISocket = "/run/x/api.sock"
	if _, err := Prepare(cfg, Logs{}); err != nil {
		t.Fatal(err)
	}
}

// A device that starts disconnected (after a crash: `thinkpol up
// -connect=false`) clears what the crashed run left for both of the data
// plane's owners on the host: the route table's and the overlay's, whose
// routes went with the utun but stayed in its record on macOS.
func TestAStartWhileDisconnectedClearsACrashedRunsRoutes(t *testing.T) {
	prevHost, prevOwner := clearHostNetwork, clearOwner
	t.Cleanup(func() { clearHostNetwork, clearOwner = prevHost, prevOwner })
	cleared := make(chan []netcfg.Owner, 4)
	clearHostNetwork = func() error {
		var owners []netcfg.Owner
		clearOwner = func(o netcfg.Owner) error { owners = append(owners, o); return nil }
		err := clearNetwork()
		cleared <- owners
		return err
	}
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startDevice(t, s, reg, false)
	select {
	case owners := <-cleared:
		if want := []netcfg.Owner{netcfg.OwnerRouteTable, netcfg.OwnerOverlay}; !slices.Equal(owners, want) {
			t.Fatalf("cleared %v, want %v", owners, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a disconnected start cleared nothing")
	}
}

// Clearing one owner failing doesn't keep the other's leftovers; an OS
// without an adapter for an owner has nothing to clear.
func TestClearingTheNetworkTriesBothOwners(t *testing.T) {
	prev := clearOwner
	t.Cleanup(func() { clearOwner = prev })
	var owners []netcfg.Owner
	clearOwner = func(o netcfg.Owner) error {
		owners = append(owners, o)
		if o == netcfg.OwnerRouteTable {
			return errors.New("no routing socket today")
		}
		return nil
	}
	err := clearNetwork()
	if !slices.Equal(owners, []netcfg.Owner{netcfg.OwnerRouteTable, netcfg.OwnerOverlay}) {
		t.Errorf("cleared %v", owners)
	}
	if err == nil || !strings.Contains(err.Error(), "route-table: no routing socket today") {
		t.Errorf("error %v", err)
	}
	clearOwner = func(netcfg.Owner) error { return fmt.Errorf("netcfg: %w", errors.ErrUnsupported) }
	if err := clearNetwork(); err != nil {
		t.Errorf("unsupported: %v", err)
	}
}
