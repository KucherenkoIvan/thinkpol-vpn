package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// ErrUnsupported is returned where a node can't run its data plane.
var ErrUnsupported = errors.New("agent: unsupported")

// DataPlane is one space's data plane on a node, as RunDataPlane runs it:
// on a device (DirectInbound), and in a server's worker (SharedInbound).
type DataPlane struct {
	Keys NodeKeys
	// Map is the map to start from, verified; the node's section in it
	// must open with Keys.
	Map *netmap.Map
	// Maps delivers envelopes of the same space, latest-wins. One is taken
	// only if Map.Next takes it (valid, signed by the space, newer);
	// otherwise the node keeps running on the map it has. A taken map
	// without a section for the node stops the data plane until a later
	// map includes the node again (it was removed from the space).
	Maps     <-chan []byte
	Registry *transport.Registry
	Inbound  Inbound
	// Interface names the TUN; empty is tun.DefaultName.
	Interface string
	// LinkMTU is the MTU of the network under the links; 0 is
	// dataplane.DefaultLinkMTU.
	LinkMTU int
	// Log gets the data plane's events. It may quote the map at debug
	// level: keep it local (stderr and the in-memory ring).
	Log *slog.Logger
	// StatusAttrs, if set, adds attributes to the periodic status line at
	// debug level (a worker's shared-listener figures).
	StatusAttrs func() []any
	// Forward makes the node its space's exit when its section allows
	// egress (dataplane.EngineConfig.Forward): set in a server's worker,
	// whose namespace forwards and NATs, never on a device.
	Forward bool

	// A device's (Node.run): where its status goes, its Connect and
	// Disconnect requests, and whether it starts disconnected.
	report       *report
	requests     <-chan connectRequest
	disconnected bool
	// Rules are the device's own rule choice (LocalRulesFile), and
	// rulesRequests replace them while it runs.
	Rules         rules.Local
	rulesRequests <-chan rulesRequest

	// What tests swap: the TUN and its configurator, the path layer's
	// timing, how long to wait before retrying what failed.
	newTUN     func(name string) (wgtun.Device, netcfg.Configurator, error)
	path       path.Options
	retryAfter time.Duration
}

// RetryAfter is how long a data plane waits before retrying an Apply, a
// start or a listener that failed.
const RetryAfter = 5 * time.Second

// statusEvery paces the status line at debug level.
const statusEvery = 30 * time.Second

// RunDataPlane runs a space's data plane until ctx ends (nil) or it can't
// start (an error, with everything it set up undone): it creates the TUN
// and its configurator, starts the engine on the node's section of Map,
// serves Inbound's listeners, and applies every newer map from Maps. On
// return the TUN, its addresses and routes, the listeners and the path
// layer are gone.
func RunDataPlane(ctx context.Context, dp DataPlane) error {
	if dp.Interface == "" {
		dp.Interface = tun.DefaultName
	}
	if dp.newTUN == nil {
		dp.newTUN = newTUN
	}
	if dp.retryAfter == 0 {
		dp.retryAfter = RetryAfter
	}
	if dp.Log == nil {
		dp.Log = slog.New(slog.DiscardHandler)
	}
	section, err := openSection(dp.Map, dp.Keys)
	if err != nil {
		return err
	}
	r := &runner{dp: dp, cur: dp.Map, section: section, maps: dp.Maps, down: dp.disconnected}
	// The first map must run: a node that can't carry it shouldn't look
	// up. A shutdown meanwhile is no failure.
	if !r.down {
		if err := r.start(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	defer r.stop()
	return r.loop(ctx)
}

// connectRequest asks a device's data plane to come up (connect) or go
// down; done gets the outcome and must have room for it.
type connectRequest struct {
	connect bool
	done    chan<- error
}

// rulesRequest replaces a device's own rules; done gets what enforcing
// them said (rules.ErrPresetUnavailable: enforced failing closed) and
// must have room for it.
type rulesRequest struct {
	rules rules.Local
	done  chan<- error
}

// newTUN takes the overlay's network configuration (one owner per network
// namespace: a second node agent here fails now, before anything changed)
// and creates the TUN; the engine sets its MTU.
func newTUN(name string) (wgtun.Device, netcfg.Configurator, error) {
	ifc, err := netcfg.New(netcfg.OwnerOverlay)
	if err != nil {
		return nil, nil, err
	}
	dev, err := tun.Create(name, 1420)
	if err != nil {
		_ = ifc.Close()
		return nil, nil, err
	}
	return dev, ifc, nil
}

// runner follows the space's maps and runs the data plane while the node
// is in the space.
type runner struct {
	dp      DataPlane
	maps    <-chan []byte
	cur     *netmap.Map
	section netmap.Section

	// engine and listeners are nil while stopped: the node was removed,
	// or starting again failed.
	engine    *dataplane.Engine
	listeners *listenerSet
	removed   bool
	// down is set while a device is disconnected: it follows the maps but
	// runs nothing.
	down bool
	// retryAt is when to retry a failed Apply or start (zero: nothing to
	// retry).
	retryAt time.Time
}

// start brings the data plane up on the current section. It fails with a
// *StartError.
func (r *runner) start(ctx context.Context) error {
	dev, ifc, err := r.dp.newTUN(r.dp.Interface)
	if err != nil {
		return &StartError{Step: StepTUN, Err: err}
	}
	engine, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID:           r.dp.Keys.ID,
		Space:        transport.SpaceID(r.cur.Header().SpaceID),
		WireGuardKey: r.dp.Keys.WireGuard,
		Registry:     r.dp.Registry,
		TUN:          dev,
		Interface:    ifc,
		LinkMTU:      r.dp.LinkMTU,
		Path:         r.dp.path,
		Log:          r.dp.Log,
		Forward:      r.dp.Forward,
		Rules:        r.dp.Rules,
	})
	if err != nil {
		if ifc != nil {
			_ = ifc.Close()
		}
		_ = dev.Close()
		return &StartError{Step: StepEngine, Err: err}
	}
	if err := engine.Apply(ctx, r.section); err != nil {
		step := engine.Status().LastApplyError
		_ = engine.Close()
		return &StartError{Step: step, Err: fmt.Errorf("applying map version %d: %w", r.cur.Header().Version, err)}
	}
	r.engine = engine
	r.listeners = newListenerSet(engine, r.dp.Log, r.dp.retryAfter)
	r.retryAt = time.Time{}
	r.applied()
	return nil
}

// stop takes the data plane down: listeners, engine, TUN and its
// configuration.
func (r *runner) stop() {
	if r.engine == nil {
		return
	}
	r.dp.report.set(func(p *report) { p.engine = nil })
	r.listeners.closeAll()
	if err := r.engine.Close(); err != nil {
		r.dp.Log.Warn("closing the data plane", "err", err)
	}
	r.listeners.wait()
	r.engine, r.listeners = nil, nil
}

func (r *runner) loop(ctx context.Context) error {
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	defer retry.Stop()
	status := time.NewTicker(statusEvery)
	defer status.Stop()
	for {
		var ended <-chan struct{}
		if r.listeners != nil {
			r.listeners.reconcile(ctx, r.dp.Inbound.Listeners(r.section))
			ended = r.listeners.ended
		}
		r.publish()
		if at, ok := r.nextRetry(); ok {
			retry.Reset(time.Until(at))
		} else {
			retry.Stop()
		}
		select {
		case <-ctx.Done():
			return nil
		case env, ok := <-r.maps:
			if !ok {
				r.maps = nil // no more maps: run on this one
				continue
			}
			r.next(ctx, env)
		case <-r.dp.Inbound.Changed():
		case <-ended:
		case <-retry.C:
			r.retry(ctx)
		case <-status.C:
			r.logStatus()
		case req := <-r.dp.requests:
			r.request(ctx, req)
		case req := <-r.dp.rulesRequests:
			r.dp.Rules = req.rules
			var err error
			if r.engine != nil {
				err = r.engine.SetRules(req.rules)
			}
			r.publish()
			req.done <- err
		}
	}
}

// publish puts the data plane's state into the device's report.
func (r *runner) publish() {
	n := 0
	if r.listeners != nil {
		n = len(r.listeners.serving)
	}
	r.dp.report.set(func(p *report) {
		p.engine, p.version, p.removed, p.retrying, p.listeners, p.want =
			r.engine, r.cur.Header().Version, r.removed, !r.retryAt.IsZero(), n, !r.down
	})
}

// request connects or disconnects a device. Connecting starts the data
// plane at once on the current map, and fails if that fails; a node
// removed from its space connects once a map includes it again. The
// report is up to date before the requester hears back.
func (r *runner) request(ctx context.Context, req connectRequest) {
	err := r.connect(ctx, req.connect)
	r.publish()
	req.done <- err
}

func (r *runner) connect(ctx context.Context, connect bool) error {
	switch {
	case !connect && !r.down:
		r.down = true
		r.stop()
		r.retryAt = time.Time{}
		r.dp.Log.Info("disconnected")
	case connect && r.removed:
		if r.down {
			r.down = false
			r.dp.Log.Info("connecting once a map includes this node")
		}
	case connect && r.engine == nil:
		// Down on purpose, or up but its start failed and waits for a
		// retry: either way it starts now, and says if it can't.
		wasDown := r.down
		r.down = false
		if err := r.start(ctx); err != nil {
			if wasDown {
				r.down = true
			} else {
				r.retryAt = time.Now().Add(r.dp.retryAfter)
			}
			r.dp.Log.Warn("connecting failed", "version", r.cur.Header().Version, "err", err)
			return err
		}
		r.dp.Log.Info("connected")
	}
	return nil
}

// nextRetry is the earliest retry due: the data plane's or a listener's.
func (r *runner) nextRetry() (time.Time, bool) {
	at, ok := r.retryAt, !r.retryAt.IsZero()
	if r.listeners != nil {
		if l, lok := r.listeners.nextRetry(); lok && (!ok || l.Before(at)) {
			at, ok = l, true
		}
	}
	return at, ok
}

// retry retries a failed start or Apply when it is due; listeners retry in
// reconcile.
func (r *runner) retry(ctx context.Context) {
	if r.down || r.retryAt.IsZero() || time.Now().Before(r.retryAt) {
		return
	}
	if r.engine == nil {
		r.tryStart(ctx)
		return
	}
	r.apply(ctx)
}

// next takes a newer map, if it is one.
func (r *runner) next(ctx context.Context, envelope []byte) {
	m, err := r.cur.Next(envelope)
	switch {
	case errors.Is(err, netmap.ErrNotNewer):
		r.dp.Log.Debug("map not newer, ignored", "version", r.cur.Header().Version)
		return
	case err != nil:
		r.dp.Log.Warn("map refused, keeping the current one", "version", r.cur.Header().Version, "err", err)
		return
	}
	section, err := openSection(m, r.dp.Keys)
	if errors.Is(err, netmap.ErrNotRecipient) {
		// A valid newer map without the node: it was removed. The map
		// is taken, so no older one that has the node can come back.
		r.cur = m
		if !r.removed {
			r.removed = true
			r.dp.Log.Warn("removed from space: the map has no section for this node; the data plane stops until a map includes it again",
				"version", m.Header().Version)
		}
		r.stop()
		r.retryAt = time.Time{}
		return
	}
	if err != nil {
		r.dp.Log.Error("map refused, keeping the current one", "version", r.cur.Header().Version, "err", err)
		return
	}
	if section.Node.Kind != r.section.Node.Kind {
		r.dp.Log.Warn("the map changes this node's kind; restart the node to change its mode", "kind", section.Node.Kind)
	}
	r.cur, r.section = m, section
	if r.engine == nil {
		if r.removed {
			r.removed = false
			r.dp.Log.Info("back in space", "version", m.Header().Version)
		}
		if !r.down {
			r.tryStart(ctx)
		}
		return
	}
	r.apply(ctx)
}

func (r *runner) tryStart(ctx context.Context) {
	if err := r.start(ctx); err != nil {
		r.retryAt = time.Now().Add(r.dp.retryAfter)
		r.dp.Log.Warn("starting the data plane failed, retrying", "version", r.cur.Header().Version, "in", r.dp.retryAfter, "err", err)
	}
}

func (r *runner) apply(ctx context.Context) {
	if err := r.engine.Apply(ctx, r.section); err != nil {
		r.retryAt = time.Now().Add(r.dp.retryAfter)
		r.dp.Log.Warn("applying the map failed, retrying", "version", r.cur.Header().Version,
			"step", r.engine.Status().LastApplyError, "in", r.dp.retryAfter, "err", err)
		return
	}
	r.retryAt = time.Time{}
	r.applied()
}

func (r *runner) applied() {
	st := r.engine.Status()
	attrs := []any{"version", r.cur.Header().Version, "node", r.dp.Keys.ID, "ipv4", r.section.Node.IPv4,
		"mtu", st.MTU, "peers", len(st.Peers), "skipped", len(st.Skipped)}
	if st.IPv6 {
		attrs = append(attrs, "ipv6", r.section.Node.IPv6)
	} else {
		attrs = append(attrs, "ipv6_off", st.IPv6Off)
	}
	if n := r.section.Node; n.Kind == netmap.NodeServer {
		attrs = append(attrs, serverSettings(n)...)
	}
	r.dp.Log.Info("map applied", attrs...)
}

// serverSettings are a server's ingress and egress settings, for its log.
func serverSettings(n netmap.NodeSettings) []any {
	return []any{"ingress", onOff(n.AllowIngress), "egress", onOff(n.AllowEgress)}
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func (r *runner) logStatus() {
	if r.engine == nil || !r.dp.Log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	st := r.engine.Status()
	handshaken, up := 0, 0
	for _, p := range st.Peers {
		if !p.LastHandshake.IsZero() {
			handshaken++
		}
	}
	for _, n := range st.Neighbors {
		for _, l := range n.Links {
			if l.Up {
				up++
			}
		}
	}
	attrs := []any{"version", r.cur.Header().Version, "peers", len(st.Peers), "handshaken", handshaken,
		"neighbors", len(st.Neighbors), "links_up", up, "listeners", len(r.listeners.serving),
		"no_path", st.Path.NoPath, "no_route", st.Router.NoRoute}
	if r.dp.StatusAttrs != nil {
		attrs = append(attrs, r.dp.StatusAttrs()...)
	}
	r.dp.Log.Debug("status", attrs...)
}

// listenerSet is what a data plane serves of its Inbound's listeners.
type listenerSet struct {
	// peers and serve are the engine's Inbound and Serve.
	peers      func(transport string) transport.Peers
	serve      func(transport string, l transport.Listener) error
	log        *slog.Logger
	retryAfter time.Duration
	// ended is signalled when a listener's Serve returned on its own.
	ended   chan struct{}
	serving map[string]*served
	// retryAt holds the listeners that failed to open or stopped on their
	// own, and when to open them again.
	retryAt map[string]time.Time
}

type served struct {
	l      transport.Listener
	closed atomic.Bool // by the set
	// failed is set, before done closes, when Serve ended on its own.
	failed bool
	done   chan struct{}
}

func newListenerSet(engine *dataplane.Engine, log *slog.Logger, retryAfter time.Duration) *listenerSet {
	return &listenerSet{
		peers: engine.Inbound, serve: engine.Serve, log: log, retryAfter: retryAfter,
		ended: make(chan struct{}, 1), serving: map[string]*served{}, retryAt: map[string]time.Time{},
	}
}

// reconcile closes the listeners not in want, and opens those in want that
// don't run and aren't waiting for a retry.
func (ls *listenerSet) reconcile(ctx context.Context, want []Listener) {
	now := time.Now()
	keep := make(map[string]bool, len(want))
	for _, l := range want {
		keep[l.Key] = true
	}
	for key, s := range ls.serving {
		if isClosed(s.done) {
			delete(ls.serving, key)
			if s.failed {
				ls.retryAt[key] = now.Add(ls.retryAfter)
			}
			continue
		}
		if !keep[key] {
			s.closed.Store(true)
			_ = s.l.Close()
			<-s.done
			delete(ls.serving, key)
			ls.log.Info("listener closed", "listener", key)
		}
	}
	for key := range ls.retryAt {
		if !keep[key] {
			delete(ls.retryAt, key)
		}
	}
	for _, l := range want {
		if ls.serving[l.Key] != nil || isClosed(l.Done) {
			continue
		}
		if at, ok := ls.retryAt[l.Key]; ok && now.Before(at) {
			continue
		}
		lst, err := l.Open(ctx, ls.peers(l.Transport))
		if err != nil {
			ls.retryAt[l.Key] = now.Add(ls.retryAfter)
			ls.log.Warn("opening a listener failed, retrying", "listener", l.Key, "in", ls.retryAfter, "err", err)
			continue
		}
		delete(ls.retryAt, l.Key)
		s := &served{l: lst, done: make(chan struct{})}
		ls.serving[l.Key] = s
		ls.log.Info("listening", "listener", l.Key, "address", lst.Addr())
		go func() {
			err := ls.serve(l.Transport, lst)
			// Decide, then mark done, then signal: reconcile sees a
			// stopped listener only once done is closed.
			s.failed = !s.closed.Load() && !isClosed(l.Done)
			if s.failed {
				ls.log.Warn("listener stopped, reopening", "listener", l.Key, "in", ls.retryAfter, "err", err)
			}
			close(s.done)
			if s.failed {
				select {
				case ls.ended <- struct{}{}:
				default:
				}
			}
		}()
	}
}

// nextRetry is when the earliest listener retry is due.
func (ls *listenerSet) nextRetry() (time.Time, bool) {
	var at time.Time
	for _, t := range ls.retryAt {
		if at.IsZero() || t.Before(at) {
			at = t
		}
	}
	return at, !at.IsZero()
}

func isClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (ls *listenerSet) closeAll() {
	for _, s := range ls.serving {
		s.closed.Store(true)
		_ = s.l.Close()
	}
}

// wait waits for every Serve to return (the engine is closed by then).
func (ls *listenerSet) wait() {
	for key, s := range ls.serving {
		<-s.done
		delete(ls.serving, key)
	}
}
