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

	// rulesMu serializes SetRulePreset; local is the device's last good
	// rules, as LocalRulesFile holds them (read by run while it builds
	// the data plane, under rulesMu).
	rulesMu       sync.Mutex
	local         rules.Local
	rulesRequests chan rulesRequest
}

// Prepare reads and checks what a node runs from (LoadState) and decides
// its mode: a node whose map is invalid, or holds no section for its keys,
// never starts. The platform is the host's adapters, per OS.
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
	}
	connect, recorded := startConnected(cfg, plat.ConnectRecord, logs)
	n.conn, n.bootChoice = newConnection(connect, st.Removed), !recorded && keepsConnect(cfg)
	n.local = st.LocalRules
	mode := cfg.Mode
	if !st.Removed {
		mode = n.resolveMode()
	}
	n.report = report{mode: mode, space: st.Trust.SpaceID, version: st.Map.Header().Version, removed: st.Removed,
		conn: n.conn.state, preset: n.local.Preset.String()}
	if mode == ModeDevice && !cfg.Connect && cfg.APISocket == "" {
		return nil, errors.New("a device that starts disconnected needs the local API to connect: set an API socket")
	}
	return n, nil
}

// keepsConnect is whether the node keeps its connect choice for the boot:
// the service's connect-on-boot is set (Validate refuses it without a
// local API).
func keepsConnect(cfg Config) bool { return cfg.ConnectOnBoot != "" }

// startConnected is whether a device starts connected: when it keeps its
// choice, as recorded in this boot (recorded true), else as
// connect-on-boot says; run by hand, as Config.Connect says. A record
// that can't be read is logged and connect-on-boot decides.
func startConnected(cfg Config, rec ConnectRecord, logs Logs) (connect, recorded bool) {
	if !keepsConnect(cfg) {
		return cfg.Connect, false
	}
	onBoot := cfg.ConnectOnBoot == ConnectOnBootOn
	connect, ok, err := rec.Load()
	switch {
	case err != nil:
		logs.Warn("the connect choice of this boot can't be read: starting as connect-on-boot says", "connect_on_boot", cfg.ConnectOnBoot, "err", err)
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

// resolveMode is the node's mode, ModeAuto decided by its kind in its
// section.
func (n *Node) resolveMode() Mode {
	switch {
	case n.cfg.Mode != ModeAuto:
		return n.cfg.Mode
	case n.state.Section.Node.Kind == netmap.NodeServer:
		return ModeServer
	}
	return ModeDevice
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
// stored in LocalRulesFile (only the service writes it), then enforced.
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
	n.rulesMu.Lock()
	defer n.rulesMu.Unlock()
	next := n.local
	next.Preset = p
	data, err := next.MarshalText()
	if err != nil {
		return err
	}
	d, err := openTrustedDir(n.cfg.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.write(LocalRulesFile, data, 0o644); err != nil {
		return err
	}
	n.local = next
	n.report.set(func(r *report) { r.preset = p.String() })
	n.logs.Info("rule preset set", "preset", p)
	done := make(chan error, 1)
	select {
	case n.rulesRequests <- rulesRequest{rules: next, done: done}:
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

// Mode is the mode the node runs in; ModeAuto while the node is removed
// from its space and its kind unknown. Safe to call from any goroutine.
func (n *Node) Mode() Mode {
	n.report.mu.Lock()
	defer n.report.mu.Unlock()
	return n.report.mode
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
	if n.state.Removed && !n.awaitSection(ctx, maps) {
		return nil
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
	}
	n.rulesMu.Lock()
	dp.Rules = n.local
	n.rulesMu.Unlock()
	dp.tuning = n.tuning
	return RunDataPlane(ctx, dp)
}

// awaitSection follows the space's maps while the node is removed from it,
// until one includes the node (true) or ctx ends (false). A node removed
// while it was down starts this way instead of failing, which under a
// service manager would only restart it over and over.
func (n *Node) awaitSection(ctx context.Context, maps <-chan []byte) bool {
	f := mapFollower{log: n.logs.Logger, keys: n.state.Keys, report: &n.report,
		removedMsg: "waiting for a map that includes it"}
	f.markRemoved(n.state.Map)
	// The report gets the map, the connection and, once back, the mode;
	// the events are told after it shows them.
	mode := ModeAuto
	publish := func() {
		n.report.set(func(p *report) {
			p.version, p.removed, p.conn = f.cur.Header().Version, f.removed, n.conn.state
			if mode != ModeAuto {
				p.mode = mode
			}
		})
	}
	publish()
	emitter(n.emit).emit(EventRemovedFromSpace, f.cur.Header().Version)
	requested := false
	for {
		select {
		case <-ctx.Done():
			// The node returns: its connection is down.
			if !n.conn.disconnected() {
				logRefused(n.logs.Logger, n.conn.disconnect())
			}
			publish()
			return false
		case req := <-n.rulesRequests:
			// Stored already: the data plane starts with them.
			req.done <- nil
		case req := <-n.requests:
			// Kept for when the node is back in its space.
			requested = true
			n.remember(req.connect)
			var err error
			switch {
			case req.connect && n.conn.disconnected():
				err = n.conn.connect(false)
			case !req.connect && !n.conn.disconnected():
				err = n.conn.disconnect()
			}
			logRefused(n.logs.Logger, err)
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
			if !back {
				publish() // still out, on a newer map
				continue
			}
			n.state.Map, n.state.Section, n.state.Removed = f.cur, f.section, false
			mode = n.resolveMode()
			if mode != ModeServer && n.conn.state == connRemoved {
				logRefused(n.logs.Logger, n.conn.resume())
			}
			publish()
			if requested && mode == ModeServer {
				n.logs.Warn("a connect or disconnect taken while removed is dropped: this node is a server, which always serves its spaces")
			}
			f.sayBack("mode", mode)
			emitter(n.emit).emit(EventBackInSpace, f.cur.Header().Version)
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
