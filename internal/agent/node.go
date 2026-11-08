package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/go-kernel/app"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Node is a node ready to run (`thinkpol up`): its configuration and state,
// read and checked, nothing on the host touched yet.
type Node struct {
	cfg   Config
	state State
	logs  Logs
	// plat is what the node needs of its host.
	plat Platform
	// conn is a device's connection, moved only by the goroutine that
	// runs the node. bootChoice: it keeps its connect choice and started
	// as configured, with no record of this boot, so its start records
	// that choice (a restart in this boot then follows it, whatever the
	// configuration says by then).
	conn       connection
	bootChoice bool
	// dnsUpstreams are cfg.DNSUpstream's.
	dnsUpstreams []netip.AddrPort

	// report holds the node's status, its mode included.
	report   report
	requests chan connectRequest
	// subscribers hear the node's events (Subscribe).
	subscribers []func(Event)
	// stopped is closed once the node's adapter returned.
	stopped chan struct{}
	// tuning is a device's data plane's (DataPlane.tuning): tests set it.
	tuning tuning
	// crashTrace is the trace file stderr goes to (KeepLastRun), until
	// the node runs as a server.
	crashTrace *CrashTrace

	// settingsMu serializes the changes to device, the member's toggles
	// as DeviceFile holds them (read by run while it builds the data
	// plane, under settingsMu).
	settingsMu sync.Mutex
	device     DeviceSettings
	// presetMu keeps SetRulePreset's store and its request to the data
	// plane in one order. Never held with settingsMu while it waits: run
	// takes settingsMu before it reads rulesRequests.
	presetMu      sync.Mutex
	rulesRequests chan rulesRequest
	// settingsChanged wakes the node's goroutine after a kill switch
	// toggle changed (SetKillSwitch, SetAllowLAN).
	settingsChanged chan struct{}
	// ks keeps a device's kill switch, on the node's goroutine.
	ks killSwitchKeeper
}

// Prepare reads and checks what a node runs from (LoadState): a node
// whose map is invalid never starts. The platform is the host's
// adapters, per OS.
func Prepare(cfg Config, logs Logs, plat Platform) (*Node, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.StateDir = filepath.Clean(cfg.StateDir)
	if cfg.MapFile != "" {
		cfg.MapFile = filepath.Clean(cfg.MapFile)
	}
	if logs.Logger == nil {
		logs.Logger = slog.New(slog.DiscardHandler)
	}
	upstreams, err := ParseUpstreams(cfg.DNSUpstream)
	if err != nil {
		return nil, err
	}
	st, err := LoadState(cfg.StateDir, cfg.MapPath())
	if err != nil {
		return nil, err
	}
	for _, name := range st.Unexpected {
		logs.Warn("the state directory holds something that isn't the node's; it is not used", "entry", name)
	}
	if st.OwnMapUnused {
		logs.Warn("the state directory's map.bin is not used: the map comes from elsewhere", "map", st.MapPath)
	}
	if plat.ConnectRecord == nil {
		return nil, errors.New("agent: the platform keeps no connect record")
	}
	n := &Node{
		cfg: cfg, state: st, logs: logs, plat: plat, dnsUpstreams: upstreams,
		requests: make(chan connectRequest), stopped: make(chan struct{}), rulesRequests: make(chan rulesRequest),
		settingsChanged: make(chan struct{}, 1),
		ks:              killSwitchKeeper{newKS: plat.NewKillSwitch, log: logs.Logger},
	}
	connect, recorded := startConnected(cfg, st.Device.ConnectOnBoot, plat.ConnectRecord, logs)
	mismatch := modeMismatch(cfg.Mode, st)
	n.conn, n.bootChoice = newConnection(connect, st.Removed || mismatch), !recorded && keepsConnect(cfg)
	n.device = st.Device
	n.report = report{mode: cfg.Mode, space: st.Trust.SpaceID, version: st.Map.Header().Version, removed: st.Removed,
		mismatch: mismatch, conn: n.conn.state, preset: n.device.Rules.Preset.String(), connectOnBoot: n.device.ConnectOnBoot}
	if ks := n.killSwitchSettings(); cfg.Mode != ModeServer {
		n.report.killSwitch = KillSwitchStatus{On: ks.on, AllowLAN: ks.allowLAN, Enforced: true}
	}
	return n, nil
}

// keepsConnect is whether the node keeps its connect choice for the boot:
// it runs as the service (Validate refuses that without a local API).
func keepsConnect(cfg Config) bool { return cfg.Service }

// startConnected is whether a device starts connected: under the service,
// as recorded in this boot (recorded true), else as the device's
// connect-on-boot (onBoot) says; run by hand, as Config.Connect says. A
// record that can't be read is logged and connect-on-boot decides.
func startConnected(cfg Config, onBoot bool, rec ConnectRecord, logs Logs) (connect, recorded bool) {
	if !keepsConnect(cfg) {
		return cfg.Connect, false
	}
	connect, ok, err := rec.Load()
	switch {
	case err != nil:
		logs.Warn("the connect choice of this boot can't be read: starting as connect-on-boot says", "connect_on_boot", onOff(onBoot), "err", err)
		return onBoot, false
	case !ok:
		return onBoot, false
	}
	logs.Info("starting as recorded in this boot", "connect", connect)
	return connect, true
}

// remember records a connect choice (ConnectRecord), when the node keeps
// it, before it is acted on; a failure is logged, and the node goes
// ahead.
func (n *Node) remember(connect bool) {
	if !keepsConnect(n.cfg) {
		return
	}
	if err := n.plat.ConnectRecord.Save(connect); err != nil {
		n.logs.Error("recording the connect request failed: a restart in this boot starts as configured", "connect", connect, "err", err)
	}
}

// ModeUnknown says why a node's mode isn't known from its state
// directory (knownMode), ModeKnown when it is.
type ModeUnknown int

const (
	ModeKnown ModeUnknown = iota
	// UnknownMapShowsServer: the node file sets no mode and the map makes
	// the node a server, say a server whose node file lost its mode.
	UnknownMapShowsServer
	// UnknownNotInMap: the node file sets no mode and the map holds no
	// section for the node (removed, or not in it yet), or can't be read.
	UnknownNotInMap
)

// knownMode is the mode a node is known to run in: its node file's (set),
// whatever its map (a device whose map is broken is one still), or, with
// none set, device by default while its map (st, unless stErr) shows it
// as one.
func knownMode(set *Mode, st State, stErr error) (Mode, ModeUnknown) {
	switch {
	case set != nil:
		return *set, ModeKnown
	case stErr != nil || st.Removed:
		return "", UnknownNotInMap
	case st.Section.Node.Kind == netmap.NodeDevice:
		return ModeDevice, ModeKnown
	}
	return "", UnknownMapShowsServer
}

// ServiceMode reads the node's state directory as `thinkpol up` would
// (an error: the node can't run yet), and says which mode its service is
// installed for: the known mode (knownMode), else server, whose
// definition keeps no crash trace (PRD S2), with why it isn't known.
func ServiceMode(dir string) (Mode, ModeUnknown, error) {
	s, err := ReadNodeFile(dir)
	if err != nil {
		return "", ModeKnown, err
	}
	st, err := LoadState(dir, filepath.Join(dir, MapFileName))
	if err != nil {
		return "", ModeKnown, err
	}
	mode, why := knownMode(s.Mode, st, nil)
	if why != ModeKnown {
		mode = ModeServer
	}
	return mode, why, nil
}

// knownDevice is whether the node of state directory dir is known to be
// a device (knownMode); a node file that can't be read says nothing.
func knownDevice(dir string) bool {
	s, err := ReadNodeFile(dir)
	if err != nil {
		return false
	}
	var st State
	if s.Mode == nil {
		st, err = LoadState(dir, filepath.Join(dir, MapFileName))
	}
	mode, why := knownMode(s.Mode, st, err)
	return why == ModeKnown && mode == ModeDevice
}

// Status reports the node's state; safe to call from any goroutine.
func (n *Node) Status() Status { return n.report.status() }

// Connect brings a device's data plane up on its latest map and returns
// once it is up, or why it failed to start (a *StartError); a device
// removed from its space comes up once a map includes it again.
// ErrServerMode on a server.
func (n *Node) Connect(ctx context.Context) error { return n.request(ctx, true) }

// Disconnect takes a device's data plane down, leaving nothing of it on
// the host, and returns once it is down. The device goes on following its
// space's maps. ErrServerMode on a server.
func (n *Node) Disconnect(ctx context.Context) error { return n.request(ctx, false) }

// SetRulePreset switches a device's rules to preset ("space",
// "everything", "all-but-domestic"), keeping its own rules: the choice is
// stored in DeviceFile (only the service writes it), then enforced.
// ErrUnknownPreset for another name; ErrPresetUnavailable when the
// space's map can't build the preset, which is then kept and enforced
// failing closed (see rules.PresetRules); ErrServerMode on a server.
func (n *Node) SetRulePreset(ctx context.Context, preset string) error {
	if n.Mode() == ModeServer {
		return ErrServerMode
	}
	p, err := rules.ParsePreset(preset)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnknownPreset, err)
	}
	n.presetMu.Lock()
	defer n.presetMu.Unlock()
	n.settingsMu.Lock()
	next := n.device
	next.Rules.Preset = p
	err = n.storeDevice(next)
	n.settingsMu.Unlock()
	if err != nil {
		return err
	}
	n.report.set(func(r *report) { r.preset = p.String() })
	n.logs.Info("rule preset set", "preset", p)
	done := make(chan error, 1)
	select {
	case n.rulesRequests <- rulesRequest{rules: next.Rules, done: done}:
	case <-n.stopped:
		return nil // stored: the next start takes it
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetConnectOnBoot sets a device's connect-on-boot, stored in DeviceFile
// (only the service writes it). It takes effect at the next boot: under
// the service, a boot's first start connects only if it is on; a start
// later in the same boot, and the running node, are left as they are.
// ErrServerMode on a server, which serves its spaces whenever it runs.
func (n *Node) SetConnectOnBoot(on bool) error {
	if n.Mode() == ModeServer {
		return ErrServerMode
	}
	n.settingsMu.Lock()
	defer n.settingsMu.Unlock()
	next := n.device
	next.ConnectOnBoot = on
	if err := n.storeDevice(next); err != nil {
		return err
	}
	n.report.set(func(r *report) { r.connectOnBoot = on })
	n.logs.Info("connect-on-boot set: from the next boot", "connect_on_boot", onOff(on))
	return nil
}

// storeDevice writes s to DeviceFile, 0600, then keeps it as the device's
// settings; on an error nothing changed. The caller holds settingsMu.
func (n *Node) storeDevice(s DeviceSettings) error {
	data, err := s.marshal()
	if err != nil {
		return err
	}
	d, err := openTrustedDir(n.cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.write(DeviceFile, data, 0o600); err != nil {
		return err
	}
	n.device = s
	return nil
}

// carryLocalRules moves a LocalRulesFile into DeviceFile, once: the
// device's preset and own rules, as read at Prepare, are written to
// DeviceFile, then rules.local is removed, and the log says so. A
// directory holding both had the move stopped after the write: rules.local
// is only removed. A server has no rules of its own: it leaves the file
// alone.
func (n *Node) carryLocalRules() error {
	if !n.state.hasLocalRules || n.Mode() == ModeServer {
		return nil
	}
	n.settingsMu.Lock()
	defer n.settingsMu.Unlock()
	if !n.state.hasDeviceFile {
		if err := n.storeDevice(n.device); err != nil {
			return fmt.Errorf("carrying %s over into %s: %w", LocalRulesFile, DeviceFile, err)
		}
		n.state.hasDeviceFile = true
	}
	d, err := openTrustedDir(n.cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.remove(LocalRulesFile, false); err != nil {
		return fmt.Errorf("%s is carried over into %s, removing it: %w", LocalRulesFile, DeviceFile, err)
	}
	n.state.hasLocalRules = false
	n.logs.Info("the device's rules moved from rules.local into device.json; rules.local is removed", "preset", n.device.Rules.Preset, "own_rules", len(n.device.Rules.Rules))
	return nil
}

func (n *Node) request(ctx context.Context, connect bool) error {
	if n.Mode() == ModeServer {
		return ErrServerMode
	}
	done := make(chan error, 1)
	select {
	case n.requests <- connectRequest{connect: connect, done: done}:
	case <-n.stopped:
		return ErrNotRunning
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Mode is the mode the node runs in (Config.Mode), fixed at Prepare.
func (n *Node) Mode() Mode { return n.cfg.Mode }

// modeMismatch is whether a node run in mode on st can't run its section:
// device mode never runs a server's (PRD A4).
func modeMismatch(mode Mode, st State) bool {
	return mode == ModeDevice && !st.Removed && st.Section.Node.Kind == netmap.NodeServer
}

// KeepLastRun keeps what TakeCrashTrace found for Status and Diagnose,
// and logs it: what was fixed of the file, and that the previous run
// crashed. Then the file is the node's to empty (CrashTrace.Release), or,
// for a server, to stop writing to (keepNoTrace). Call it before the node
// runs; a file it can't empty fails the start, stderr detached.
func (n *Node) KeepLastRun(ct *CrashTrace) error {
	if ct.Fixed != "" {
		n.logs.Warn("the crash trace file was wider than root's 0600; fixed", "file", CrashTraceFile, "fixed", ct.Fixed)
	}
	switch {
	case ct.LastRun.Crashed():
		n.logs.Warn("the previous run crashed or exited with an error; thinkpol diag shows its trace (root only)")
	case ct.LastRun.Unreadable != "":
		n.logs.Warn("the previous run's crash trace wasn't read", "why", ct.LastRun.Unreadable)
	}
	n.report.set(func(p *report) { p.lastRun = ct.LastRun })
	n.crashTrace = ct
	if n.Mode() == ModeServer {
		n.keepNoTrace()
		return nil
	}
	return ct.Release()
}

// keepNoTrace stops a server's stderr going to a crash trace (PRD S2: a
// server keeps no logs on disk): under a device's definition (its node
// file set device mode when it was installed), the file is emptied and
// removed, and stderr goes nowhere. A trace file left in the state
// directory is warned about.
func (n *Node) keepNoTrace() {
	if ct := n.crashTrace; ct != nil && ct.Tracing {
		if err := ct.detach(false); err != nil {
			n.logs.Error("a server's stderr still goes to the crash trace file", "err", err)
		}
		n.logs.Warn("a server under a device's service definition: run thinkpol service install; its stderr goes nowhere and the crash trace file is removed")
	}
	if _, err := os.Lstat(filepath.Join(n.cfg.StateDir, CrashTraceFile)); err == nil {
		n.logs.Warn("the state directory holds a crash trace, which a server keeps none of; it is not used (thinkpol service install removes it)", "entry", CrashTraceFile)
	}
}

// Subscribe has f hear the node's events, each once Status shows what it
// says, on the goroutine that runs the node: f must return quickly, and
// may read Status but not call Connect, Disconnect or SetRulePreset, which
// wait for that goroutine. A panic in f is logged, not the node's end.
// Call it before the node runs.
func (n *Node) Subscribe(f func(Event)) { n.subscribers = append(n.subscribers, f) }

func (n *Node) emit(ev Event) {
	for _, f := range n.subscribers {
		n.tell(f, ev)
	}
}

func (n *Node) tell(f func(Event), ev Event) {
	defer func() {
		if p := recover(); p != nil {
			n.logs.Error("an event subscriber panicked", "event", ev.Kind, "panic", p)
		}
	}()
	f(ev)
}

// State is what the node runs from.
func (n *Node) State() State { return n.state }

// Adapters are what runs the node, for the caller to run with go-kernel's
// app.Run next to its own (the local API): the map watcher and the node.
// Together they run the node until ctx ends or one fails, and undo
// everything the node set up before returning: a clean stop leaves no
// interface, route, namespace or nftables table behind. reload (SIGHUP)
// makes the watcher read the map file at once. A node removed from its
// space (its map has no section for it) waits idle for a map that includes
// it. On a host whose data plane isn't there yet, or where another node
// agent runs (it holds the host's agent lock), Adapters refuses, before
// anything changed. The lock is held until the node adapter returns, or
// the process ends. Call it once.
func (n *Node) Adapters(reload <-chan os.Signal) ([]app.Adapter, error) {
	if err := supported(n.Mode()); err != nil {
		return nil, err
	}
	// One node agent per host, taken before anything of this node (or the
	// caller's adapters) touches the host: a second agent would undo the
	// first's routes and resolver configuration with run's cleanups.
	unlock, err := n.plat.LockHost()
	if err != nil {
		return nil, err
	}
	// Under the host lock, so two starts never carry it over at once.
	if err := n.carryLocalRules(); err != nil {
		unlock()
		return nil, err
	}
	reg, err := n.plat.Transports(true)
	if err != nil {
		unlock()
		return nil, err
	}
	watcher := &mapWatcher{path: n.state.MapPath, interval: n.cfg.MapPoll, reload: reload, log: n.logs.Logger, last: n.state.mapFile}
	maps := make(chan []byte, 1)
	return []app.Adapter{
		{Name: "map watcher", Run: func(ctx context.Context) error { return watcher.run(ctx, maps) }},
		{Name: "node", Run: func(ctx context.Context) error {
			defer unlock()
			return n.run(ctx, reg, maps)
		}},
	}, nil
}

func (n *Node) run(ctx context.Context, reg *transport.Registry, maps chan []byte) error {
	defer close(n.stopped)
	h := n.state.Map.Header()
	n.logs.Info("starting", "mode", n.Mode(), "space", h.SpaceID, "node", n.state.Keys.ID, "version", h.Version, "map", n.state.MapPath)
	if n.bootChoice && n.Mode() != ModeServer {
		n.remember(!n.conn.disconnected())
	}
	// A server's section in device mode (a server whose node file lost
	// its mode) leaves the host alone: nothing is put back or taken over
	// until a map makes the node a device.
	mismatch := modeMismatch(n.Mode(), n.state)
	if !mismatch {
		n.restoreHost()
		n.startKillSwitch(ctx)
	}
	if (n.state.Removed || mismatch) && !n.awaitSection(ctx, maps) {
		return nil
	}
	if mismatch {
		n.restoreHost()
		n.startKillSwitch(ctx)
	}
	if n.Mode() == ModeServer {
		return n.runServer(ctx, reg, maps)
	}
	log := n.logs.With("space", n.state.Trust.SpaceID.String())
	dp := DataPlane{
		Keys:         n.state.Keys,
		Map:          n.state.Map,
		Maps:         maps,
		Registry:     reg,
		Inbound:      DirectInbound(reg),
		Interface:    n.cfg.Interface,
		LinkMTU:      n.cfg.LinkMTU,
		Log:          log,
		Blobs:        blobs.NewOnNet(blobs.Options{Store: diskBlobs{dir: n.cfg.StateDir, log: log}, Log: log}, n.plat.BlobNet),
		DNS:          n.cfg.DNS,
		DNSUpstreams: n.dnsUpstreams,
		RouteTable:   true,
		Namespace:    n.plat.WorkerHost,
		Device:       &n.plat.DeviceHost,

		report:        &n.report,
		conn:          &n.conn,
		requests:      n.requests,
		remember:      n.remember,
		events:        n.emit,
		rulesRequests: n.rulesRequests,

		killSwitch:      n.enforceKillSwitch,
		settingsChanged: n.settingsChanged,
	}
	n.settingsMu.Lock()
	dp.Rules = n.device.Rules
	n.settingsMu.Unlock()
	dp.tuning = n.tuning
	return RunDataPlane(ctx, dp)
}

// startKillSwitch puts a device's kill switch as it starts: a crashed or
// stopped run's is narrowed to the down shape (or removed, if not meant)
// before anything connects.
func (n *Node) startKillSwitch(ctx context.Context) {
	if n.Mode() == ModeServer {
		return
	}
	v := killSwitchView{meantUp: !n.conn.disconnected()}
	if !n.state.Removed {
		v.entries = entries(n.state.Section)
	}
	n.enforceKillSwitch(ctx, v)
}

// restoreHost puts back what a crashed run left on the host.
func (n *Node) restoreHost() {
	if n.Mode() != ModeServer && n.conn.state != connConnecting {
		// What the data plane left in the host's routing when the node
		// died connected (a crash, kill -9): a device that starts
		// without connecting has nothing holding it, and connecting
		// takes it over anyway.
		n.plat.clearNetwork(n.logs.Logger)
	}
	// A resolver configuration a crash left behind goes back first,
	// whatever the node does next.
	if err := n.plat.RestoreDNS(); err != nil {
		n.logs.Warn("DNS: restoring the system's resolver configuration left behind", "err", err)
	}
}

// awaitSection follows the space's maps while the node runs nothing of
// them, removed from its space or, in device mode, made a server by its
// map, until one gives the node a section it runs (true) or ctx ends
// (false). A node removed while it was down starts this way instead of
// failing, which under a service manager would only restart it over and
// over; so does a device-mode node the map makes a server.
func (n *Node) awaitSection(ctx context.Context, maps <-chan []byte) bool {
	f := mapFollower{log: n.logs.Logger, keys: n.state.Keys, report: &n.report,
		removedMsg: "waiting for a map that includes it", device: n.Mode() == ModeDevice}
	if n.state.Removed {
		f.markRemoved(n.state.Map)
	} else {
		f.cur, f.section = n.state.Map, n.state.Section
		f.checkKind()
	}
	// The report gets the map and the connection; the events are told
	// after it shows them.
	publish := func() {
		n.report.set(func(p *report) {
			p.version, p.removed, p.mismatch, p.conn = f.cur.Header().Version, f.removed, f.mismatch, n.conn.state
		})
	}
	// Removed (not a server's section): the kill switch lets out no entry,
	// as the device has none.
	keepKillSwitch := func(ctx context.Context, meantUp bool) {
		if n.Mode() == ModeDevice && !f.mismatch {
			n.enforceKillSwitch(ctx, killSwitchView{meantUp: meantUp})
		}
	}
	reapply := time.NewTicker(killSwitchReapply)
	defer reapply.Stop()
	publish()
	if f.removed {
		emitter(n.emit).emit(EventRemovedFromSpace, f.cur.Header().Version)
	}
	sayBack := func() {
		f.sayBack("mode", n.Mode())
		emitter(n.emit).emit(EventBackInSpace, f.cur.Header().Version)
	}
	for {
		select {
		case <-ctx.Done():
			// The node returns: its connection is down; its kill switch
			// stays as a crash would leave it (runner.shutdown).
			meantUp := !n.conn.disconnected()
			if meantUp {
				logRefused(n.logs.Logger, n.conn.disconnect())
			}
			keepKillSwitch(context.Background(), meantUp)
			publish()
			return false
		case <-reapply.C:
			keepKillSwitch(ctx, !n.conn.disconnected())
		case <-n.settingsChanged:
			keepKillSwitch(ctx, !n.conn.disconnected())
		case req := <-n.rulesRequests:
			// Stored already: the data plane starts with them.
			keepKillSwitch(ctx, !n.conn.disconnected())
			req.done <- nil
		case req := <-n.requests:
			// Kept for when the node runs its section.
			n.remember(req.connect)
			var err error
			switch {
			case req.connect && n.conn.disconnected():
				err = n.conn.connect(false)
			case !req.connect && !n.conn.disconnected():
				err = n.conn.disconnect()
			}
			logRefused(n.logs.Logger, err)
			keepKillSwitch(ctx, !n.conn.disconnected())
			publish()
			req.done <- err
		case env, ok := <-maps:
			if !ok {
				maps = nil
				continue
			}
			taken, _, back := f.take(env)
			if !taken {
				continue
			}
			if f.out() {
				publish() // still out, on a newer map
				if back {
					sayBack()
				}
				continue
			}
			n.state.Map, n.state.Section, n.state.Removed = f.cur, f.section, false
			if n.Mode() != ModeServer && n.conn.state == connRemoved {
				logRefused(n.logs.Logger, n.conn.resume())
			}
			publish()
			if back {
				sayBack()
			}
			return true
		}
	}
}

// serverRemovedMsg completes the removal warning for a server's spaces:
// its worker and listeners stop until a map includes it again.
const serverRemovedMsg = "its worker and listeners stop until a map includes it again"

// runServer runs the supervisor, and gives it the node's space (its
// worker's config and inbound links) and the node's listeners from every
// map, until ctx ends; the supervisor is closed on return.
func (n *Node) runServer(ctx context.Context, reg *transport.Registry, maps chan []byte) error {
	level, _ := ParseLevel(n.cfg.LogLevel)
	own := n.state.Trust.SpaceID
	out := &workerOutput{w: logOutput(n.logs)}
	allowed, err := n.cfg.EgressAllowedPrefixes()
	if err != nil {
		return err
	}
	sup, err := supervisor.New(supervisor.Options{
		Transports:    reg,
		EgressAllowed: allowed,
		Log:           n.logs.With("component", "supervisor"),
		// Workers log at the node's level. Their output goes to their
		// space's ring; only the node owner's space's also goes into the
		// node's log stream, never a guest's
		// (docs/design/security.md "Rules", rule 6).
		Env:    []string{"THINKPOL_LOG_LEVEL=" + level.String()},
		Output: ownerOutput(own, out),
		// The root namespace's owner, from the same host adapters the
		// device's data plane would take.
		NewRoot: func() (netcfg.Configurator, error) { return n.plat.NewConfigurator(netcfg.OwnerSupervisor) },
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := sup.Close(); err != nil {
			n.logs.Warn("closing the supervisor", "err", err)
		}
	}()
	// Cleared before the supervisor closes (deferred calls run last first).
	n.report.set(func(p *report) { p.workers = sup })
	defer n.report.set(func(p *report) { p.workers, p.dnsUpstreamsRefused = nil, 0 })
	s := &serverSpaces{
		sup: sup, reg: reg, trust: n.state.Trust,
		iface: n.cfg.Interface, linkMTU: n.cfg.LinkMTU,
		dns: n.cfg.DNS, dnsUpstreams: n.dnsUpstreams, egressAllowed: allowed,
		retryAfter: RetryAfter, report: &n.report, requests: n.requests, rulesRequests: n.rulesRequests,
		stateDir: n.cfg.StateDir, log: n.logs.Logger,
		follow: mapFollower{
			log: n.logs.Logger, keys: n.state.Keys, report: &n.report, cur: n.state.Map, section: n.state.Section,
			removedMsg: serverRemovedMsg,
		},
		events: n.emit,
	}
	return s.run(ctx, maps)
}

// ownerOutput copies the node owner's space's worker output to out; a
// guest space's stays in its ring.
func ownerOutput(own netmap.SpaceID, out *workerOutput) func(netmap.SpaceID) io.Writer {
	return func(space netmap.SpaceID) io.Writer {
		if space != own {
			return nil
		}
		return out.forSpace(space)
	}
}

// spaceServer is what serverSpaces drives: the supervisor.
type spaceServer interface {
	SetSpaces([]supervisor.Space) error
	SetListeners([]supervisor.Listener) error
	Egress() supervisor.EgressInfo
}

// serverSpaces keeps the supervisor serving the node's current map; the
// map it follows is its follow.
type serverSpaces struct {
	sup        spaceServer
	reg        *transport.Registry
	trust      netmap.Trust
	iface      string
	linkMTU    int
	retryAfter time.Duration
	log        *slog.Logger
	// stateDir holds the seeds of the space's blobs (seedBlobs).
	stateDir string
	// dns runs the space's resolver in its worker, asking dnsUpstreams,
	// else the default public resolvers (defaultWorkerUpstreams).
	// egressAllowed are the prefixes the worker's egress allows anyway
	// (Options.EgressAllowed): an upstream outside them that the egress
	// refuses is not configured.
	dns           bool
	dnsUpstreams  []netip.AddrPort
	egressAllowed []netip.Prefix
	// refusedLogged is the last set of upstreams the egress refused, so
	// they are warned about once per change: apply reruns while
	// listeners fail.
	refusedLogged []netip.AddrPort

	// follow is the map the server follows (its section, its removals).
	follow mapFollower
	// events hears the server's removals and returns.
	events emitter

	// report gets the map's version and whether serving it failed;
	// requests, a device's, are refused.
	report        *report
	requests      <-chan connectRequest
	rulesRequests <-chan rulesRequest
}

// errListeners is SetListeners failing: the other listeners are served,
// the failed ones retried.
type errListeners struct{ error }

func (e errListeners) Unwrap() error { return e.error }

// apply gives the supervisor the current map: the space (whose worker
// gets the map and keys) and the listeners. Only the node owner's space is
// served until hosting grants (TP-040) add guests.
func (s *serverSpaces) apply() error {
	if s.follow.removed {
		// Rejoining with the same refused set warns about it again.
		s.refusedLogged = nil
		s.report.set(func(p *report) { p.dnsUpstreamsRefused = 0 })
		if err := s.sup.SetListeners(nil); err != nil {
			return errListeners{err}
		}
		return s.sup.SetSpaces(nil)
	}
	id := s.follow.cur.Header().SpaceID
	// The worker config's upstream order comes from this snapshot, taken
	// before SetSpaces finds the uplink again.
	e := s.sup.Egress()
	config, err := WorkerConfig{
		Keys: s.follow.keys, Trust: s.trust, Map: s.follow.cur.Bytes(), Interface: s.iface, LinkMTU: s.linkMTU,
		DNS: s.dns, DNSUpstreams: s.workerUpstreams(e),
	}.Encode()
	if err != nil {
		return err
	}
	inbound := dataplane.AcceptedInbound(s.follow.section, s.reg, transport.SpaceID(id), s.linkMTU)
	// The seeds are read when the supervisor sends them (a worker's start,
	// a new map), never held here.
	var seeds func() [][]byte
	if dir, header, log := s.stateDir, s.follow.cur.Header().Blobs, s.log; dir != "" && len(header) > 0 {
		seeds = func() [][]byte { return seedBlobs(dir, header, log) }
	}
	allow := s.follow.section.Node.AllowEgress
	space := supervisor.Space{
		ID: id, Config: config, Inbound: inbound.Links, Seeds: seeds,
		Egress: supervisor.EgressGrant{IPv4: allow, IPv6: allow}, Dials: dials(s.follow.section, s.reg),
	}
	if err := s.sup.SetSpaces([]supervisor.Space{space}); err != nil {
		return fmt.Errorf("serving space %v: %w", id, err)
	}
	ls := make([]supervisor.Listener, 0, len(s.follow.section.Node.Listeners))
	for _, l := range s.follow.section.Node.Listeners {
		ls = append(ls, supervisor.Listener{Transport: l.Transport, Address: l.Address.String(), Settings: l.Settings})
	}
	if err := s.sup.SetListeners(ls); err != nil {
		return errListeners{err}
	}
	// The line says what the tables enforce: SetSpaces finds the uplink
	// again before building them, so the egress is read once more, for
	// this line alone (the config's order keeps the snapshot taken
	// before).
	s.log.Info("map applied", append(append([]any{"version", s.follow.cur.Header().Version, "listeners", len(ls), "inbound_skipped", len(inbound.Skipped)},
		serverSettings(s.follow.section.Node)...), append(s.egressAttrs(s.sup.Egress()), "blobs", len(s.follow.cur.Header().Blobs))...)...)
	return nil
}

// egressAttrs say, for a section allowing egress, what the node can give
// it: the uplink and its families, never a destination.
func (s *serverSpaces) egressAttrs(e supervisor.EgressInfo) []any {
	if !s.follow.section.Node.AllowEgress {
		return nil
	}
	if e.Uplink == "" {
		s.log.Warn("egress is on but the node has no uplink: the space's internet traffic is dropped", "err", e.Err)
		return []any{"uplink", "none"}
	}
	return []any{"uplink", e.Uplink, "egress_ipv4", onOff(e.IPv4), "egress_ipv6", onOff(e.IPv6)}
}

// dials are the endpoints the section's links dial, in their transport's
// protocol: the worker reaches them out of its namespace whatever the
// egress. An endpoint of a transport the node doesn't have is never dialed.
func dials(section netmap.Section, reg *transport.Registry) []supervisor.Dial {
	var out []supervisor.Dial
	for _, l := range section.Links {
		for _, e := range l.Endpoints {
			t, ok := reg.Get(e.Transport)
			if !ok || !e.Address.IsValid() || e.Address.Port() == 0 {
				continue
			}
			d := supervisor.Dial{Address: netip.AddrPortFrom(e.Address.Addr().Unmap(), e.Address.Port()), Network: t.Network()}
			if !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}

// run serves the current map, then every newer one, until ctx ends. Only
// the first SetSpaces failing is fatal (the node can't serve its space);
// anything else is retried.
func (s *serverSpaces) run(ctx context.Context, maps <-chan []byte) error {
	var retry <-chan time.Time
	if err := s.apply(); err != nil {
		if !errors.As(err, new(errListeners)) {
			return err
		}
		s.log.Warn("opening listeners failed, retrying", "in", s.retryAfter, "err", err)
		retry = time.After(s.retryAfter)
	}
	// told are the events to tell once the report shows them.
	var told []EventKind
	for {
		s.report.set(func(p *report) {
			p.version, p.removed, p.retrying = s.follow.cur.Header().Version, s.follow.removed, retry != nil
		})
		for _, kind := range told {
			s.events.emit(kind, s.follow.cur.Header().Version)
		}
		told = nil
		select {
		case <-ctx.Done():
			return nil
		case req := <-s.requests:
			req.done <- ErrServerMode
			continue
		case req := <-s.rulesRequests:
			req.done <- ErrServerMode
			continue
		case <-retry:
		case env, ok := <-maps:
			if !ok {
				maps = nil
				continue
			}
			taken, removed, back := s.follow.take(env)
			if !taken {
				continue
			}
			if removed {
				told = append(told, EventRemovedFromSpace)
			}
			if back {
				s.follow.sayBack()
				told = append(told, EventBackInSpace)
			}
		}
		if err := s.apply(); err != nil {
			s.log.Warn("serving the map failed, retrying", "version", s.follow.cur.Header().Version, "in", s.retryAfter, "err", err)
			retry = time.After(s.retryAfter)
		} else {
			retry = nil
		}
	}
}

// logOutput is where the node's own log lines go: stderr and the ring.
func logOutput(l Logs) io.Writer {
	if l.out == nil {
		return io.Discard
	}
	return l.out
}
