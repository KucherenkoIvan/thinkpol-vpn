package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KucherenkoIvan/go-kernel/app"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Node is a node ready to run (`thinkpol up`): its configuration and state,
// read and checked, nothing on the host touched yet.
type Node struct {
	cfg   Config
	state State
	mode  Mode
	logs  Logs
	// want is set while a device is meant to be connected.
	want bool

	report   report
	requests chan connectRequest
	// stopped is closed once the node's adapter returned.
	stopped chan struct{}
	// tweak, if set, adjusts a device's DataPlane: what tests swap.
	tweak func(*DataPlane)

	// rulesMu serializes SetRulePreset; local is the device's last good
	// rules, as LocalRulesFile holds them (read by run while it builds
	// the data plane, under rulesMu).
	rulesMu       sync.Mutex
	local         rules.Local
	rulesRequests chan rulesRequest
}

// Prepare reads and checks what a node runs from (LoadState) and decides
// its mode: a node whose map is invalid, or holds no section for its keys,
// never starts.
func Prepare(cfg Config, logs Logs) (*Node, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	cfg.StateDir = filepath.Clean(cfg.StateDir)
	if cfg.MapFile != "" {
		cfg.MapFile = filepath.Clean(cfg.MapFile)
	}
	if logs.Logger == nil {
		logs.Logger = slog.New(slog.DiscardHandler)
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
	n := &Node{
		cfg: cfg, state: st, mode: cfg.Mode, logs: logs, want: cfg.Connect,
		requests: make(chan connectRequest), stopped: make(chan struct{}), rulesRequests: make(chan rulesRequest),
	}
	n.local = st.LocalRules
	n.report = report{space: st.Trust.SpaceID, version: st.Map.Header().Version, removed: st.Removed, want: n.want,
		preset: n.local.Preset.String()}
	if !st.Removed {
		n.resolveMode()
	}
	n.report.mode = n.mode
	if n.mode == ModeDevice && !cfg.Connect && cfg.APISocket == "" {
		return nil, errors.New("a device that starts disconnected needs the local API to connect: set an API socket")
	}
	return n, nil
}

// resolveMode decides ModeAuto by the node's kind in its section.
func (n *Node) resolveMode() {
	if n.cfg.Mode != ModeAuto {
		return
	}
	n.mode = ModeDevice
	if n.state.Section.Node.Kind == netmap.NodeServer {
		n.mode = ModeServer
	}
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
	n.report.mu.Lock()
	mode := n.report.mode
	n.report.mu.Unlock()
	if mode == ModeServer {
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
	n.report.mu.Lock()
	mode := n.report.mode
	n.report.mu.Unlock()
	if mode == ModeServer {
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
// from its space and its kind unknown.
func (n *Node) Mode() Mode { return n.mode }

// State is what the node runs from.
func (n *Node) State() State { return n.state }

// Adapters are what runs the node, for the caller to run with go-kernel's
// app.Run next to its own (the local API): the map watcher and the node.
// Together they run the node until ctx ends or one fails, and undo
// everything the node set up before returning: a clean stop leaves no
// interface, route, namespace or nftables table behind. reload (SIGHUP)
// makes the watcher read the map file at once. A node removed from its
// space (its map has no section for it) waits idle for a map that includes
// it. On a host whose data plane isn't there yet Adapters refuses, before
// anything changed. Call it once.
func (n *Node) Adapters(reload <-chan os.Signal) ([]app.Adapter, error) {
	if err := supported(); err != nil {
		return nil, err
	}
	reg, err := Transports(true) // a device's, or the supervisor's in the root namespace
	if err != nil {
		return nil, err
	}
	watcher := &mapWatcher{path: n.state.MapPath, interval: n.cfg.MapPoll, reload: reload, log: n.logs.Logger, last: n.state.mapFile}
	maps := make(chan []byte, 1)
	return []app.Adapter{
		{Name: "map watcher", Run: func(ctx context.Context) error { return watcher.run(ctx, maps) }},
		{Name: "node", Run: func(ctx context.Context) error { return n.run(ctx, reg, maps) }},
	}, nil
}

func (n *Node) run(ctx context.Context, reg *transport.Registry, maps chan []byte) error {
	defer close(n.stopped)
	h := n.state.Map.Header()
	n.logs.Info("starting", "mode", n.mode, "space", h.SpaceID, "node", n.state.Keys.ID, "version", h.Version, "map", n.state.MapPath)
	if n.state.Removed && !n.awaitSection(ctx, maps) {
		return nil
	}
	if n.mode == ModeServer {
		return n.runServer(ctx, reg, maps)
	}
	log := n.logs.With("space", n.state.Trust.SpaceID.String())
	dp := DataPlane{
		Keys:       n.state.Keys,
		Map:        n.state.Map,
		Maps:       maps,
		Registry:   reg,
		Inbound:    DirectInbound(reg),
		Interface:  n.cfg.Interface,
		LinkMTU:    n.cfg.LinkMTU,
		Log:        log,
		Blobs:      blobs.New(blobs.Options{Store: diskBlobs{dir: n.cfg.StateDir, log: log}, Log: log}),
		RouteTable: true,

		report:        &n.report,
		requests:      n.requests,
		disconnected:  !n.want,
		rulesRequests: n.rulesRequests,
	}
	n.rulesMu.Lock()
	dp.Rules = n.local
	n.rulesMu.Unlock()
	if n.tweak != nil {
		n.tweak(&dp)
	}
	return RunDataPlane(ctx, dp)
}

// awaitSection follows the space's maps while the node is removed from it,
// until one includes the node (true) or ctx ends (false). A node removed
// while it was down starts this way instead of failing, which under a
// service manager would only restart it over and over.
func (n *Node) awaitSection(ctx context.Context, maps <-chan []byte) bool {
	n.logs.Warn("removed from space: the map has no section for this node; waiting for a map that includes it",
		"version", n.state.Map.Header().Version)
	requested := false
	for {
		select {
		case <-ctx.Done():
			return false
		case req := <-n.rulesRequests:
			// Stored already: the data plane starts with them.
			req.done <- nil
		case req := <-n.requests:
			// Kept for when the node is back in its space.
			n.want, requested = req.connect, true
			n.report.set(func(p *report) { p.want = n.want })
			req.done <- nil
		case env, ok := <-maps:
			if !ok {
				maps = nil
				continue
			}
			m, err := n.state.Map.Next(env)
			if errors.Is(err, netmap.ErrNotNewer) {
				continue
			}
			if err != nil {
				n.logs.Warn("map refused, keeping the current one", "version", n.state.Map.Header().Version, "err", err)
				continue
			}
			section, err := openSection(m, n.state.Keys)
			if errors.Is(err, netmap.ErrNotRecipient) {
				n.state.Map = m
				n.report.set(func(p *report) { p.version = m.Header().Version })
				continue
			}
			if err != nil {
				n.logs.Error("map refused, keeping the current one", "version", n.state.Map.Header().Version, "err", err)
				continue
			}
			n.state.Map, n.state.Section, n.state.Removed = m, section, false
			n.resolveMode()
			n.report.set(func(p *report) { p.mode, p.version, p.removed = n.mode, m.Header().Version, false })
			if requested && n.mode == ModeServer {
				n.logs.Warn("a connect or disconnect taken while removed is dropped: this node is a server, which always serves its spaces")
			}
			n.logs.Info("back in space", "version", m.Header().Version, "mode", n.mode)
			return true
		}
	}
}

// runServer runs the supervisor, and gives it the node's space (its
// worker's config and inbound links) and the node's listeners from every
// map, until ctx ends; the supervisor is closed on return.
func (n *Node) runServer(ctx context.Context, reg *transport.Registry, maps chan []byte) error {
	level, _ := ParseLevel(n.cfg.LogLevel)
	own := n.state.Trust.SpaceID
	out := &workerOutput{w: logOutput(n.logs)}
	sup, err := supervisor.New(supervisor.Options{
		Transports: reg,
		Log:        n.logs.With("component", "supervisor"),
		// Workers log at the node's level. Their output goes to their
		// space's ring; only the node owner's space's also goes into the
		// node's log stream, never a guest's (DESIGN rule 6).
		Env:    []string{"THINKPOL_LOG_LEVEL=" + level.String()},
		Output: ownerOutput(own, out),
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
	defer n.report.set(func(p *report) { p.workers = nil })
	s := &serverSpaces{
		sup: sup, reg: reg, log: n.logs.Logger, keys: n.state.Keys, trust: n.state.Trust,
		iface: n.cfg.Interface, linkMTU: n.cfg.LinkMTU, cur: n.state.Map, section: n.state.Section,
		retryAfter: RetryAfter, report: &n.report, requests: n.requests, rulesRequests: n.rulesRequests,
		stateDir: n.cfg.StateDir,
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
}

// serverSpaces keeps the supervisor serving the node's current map.
type serverSpaces struct {
	sup        spaceServer
	reg        *transport.Registry
	log        *slog.Logger
	keys       NodeKeys
	trust      netmap.Trust
	iface      string
	linkMTU    int
	retryAfter time.Duration
	// stateDir holds the seeds of the space's blobs (seedBlobs).
	stateDir string

	cur     *netmap.Map
	section netmap.Section
	// removed is set while the current map has no section for the node:
	// the space's worker and the listeners are stopped.
	removed bool

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
	if s.removed {
		if err := s.sup.SetListeners(nil); err != nil {
			return errListeners{err}
		}
		return s.sup.SetSpaces(nil)
	}
	id := s.cur.Header().SpaceID
	config, err := WorkerConfig{
		Keys: s.keys, Trust: s.trust, Map: s.cur.Bytes(), Interface: s.iface, LinkMTU: s.linkMTU,
	}.Encode()
	if err != nil {
		return err
	}
	inbound := dataplane.AcceptedInbound(s.section, s.reg, transport.SpaceID(id), s.linkMTU)
	// The seeds are read when the supervisor sends them (a worker's start,
	// a new map), never held here.
	var seeds func() [][]byte
	if dir, header, log := s.stateDir, s.cur.Header().Blobs, s.log; dir != "" && len(header) > 0 {
		seeds = func() [][]byte { return seedBlobs(dir, header, log) }
	}
	if err := s.sup.SetSpaces([]supervisor.Space{{ID: id, Config: config, Inbound: inbound.Links, Seeds: seeds}}); err != nil {
		return fmt.Errorf("serving space %v: %w", id, err)
	}
	ls := make([]supervisor.Listener, 0, len(s.section.Node.Listeners))
	for _, l := range s.section.Node.Listeners {
		ls = append(ls, supervisor.Listener{Transport: l.Transport, Address: l.Address.String(), Settings: l.Settings})
	}
	if err := s.sup.SetListeners(ls); err != nil {
		return errListeners{err}
	}
	s.log.Info("map applied", append(append([]any{"version", s.cur.Header().Version, "listeners", len(ls), "inbound_skipped", len(inbound.Skipped)},
		serverSettings(s.section.Node)...), "blobs", len(s.cur.Header().Blobs))...)
	return nil
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
	for {
		s.report.set(func(p *report) { p.version, p.removed, p.retrying = s.cur.Header().Version, s.removed, retry != nil })
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
			if !s.next(env) {
				continue
			}
		}
		if err := s.apply(); err != nil {
			s.log.Warn("serving the map failed, retrying", "version", s.cur.Header().Version, "in", s.retryAfter, "err", err)
			retry = time.After(s.retryAfter)
		} else {
			retry = nil
		}
	}
}

// next takes a newer map if it is one, and reports whether it did.
func (s *serverSpaces) next(env []byte) bool {
	m, err := s.cur.Next(env)
	if errors.Is(err, netmap.ErrNotNewer) {
		s.log.Debug("map not newer, ignored", "version", s.cur.Header().Version)
		return false
	}
	if err != nil {
		s.log.Warn("map refused, keeping the current one", "version", s.cur.Header().Version, "err", err)
		return false
	}
	section, err := openSection(m, s.keys)
	if errors.Is(err, netmap.ErrNotRecipient) {
		s.cur = m
		if !s.removed {
			s.removed = true
			s.log.Warn("removed from space: the map has no section for this node; its worker and listeners stop until a map includes it again",
				"version", m.Header().Version)
		}
		return true
	}
	if err != nil {
		s.log.Error("map refused, keeping the current one", "version", s.cur.Header().Version, "err", err)
		return false
	}
	if section.Node.Kind != s.section.Node.Kind {
		s.log.Warn("the map changes this node's kind; restart the node to change its mode", "kind", section.Node.Kind)
	}
	if s.removed {
		s.removed = false
		s.log.Info("back in space", "version", m.Header().Version)
	}
	s.cur, s.section = m, section
	return true
}

// logOutput is where the node's own log lines go: stderr and the ring.
func logOutput(l Logs) io.Writer {
	if l.out == nil {
		return io.Discard
	}
	return l.out
}
