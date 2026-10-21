package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
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
	// Interface names the TUN to create; empty is tun.DefaultName. On
	// macOS the kernel may pick the name ("utun" is the next free utunN):
	// the data plane goes by the TUN's own name once it exists.
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
	// RouteTable enforces the rules in the OS routing table: everything
	// but direct destinations and link endpoints into the TUN (a device;
	// the transports' sockets must be marked, Transports(true)).
	RouteTable bool
	// Blobs, if set, holds and fetches the blobs the map names (lists):
	// RunDataPlane runs it, and gives it each map's plan once the map is
	// applied. ServeBlobs (a server's worker) also serves them, and holds
	// the header's whole set to pass on; otherwise the node only fetches
	// its own (a device, or a server run in device mode).
	Blobs      *blobs.Service
	ServeBlobs bool
	// DNS runs the node's resolver on its overlay addresses (see
	// dataplane's dnsConfig for what it serves), asking DNSUpstreams: a
	// device with none asks the resolvers the OS used before, a worker
	// never falls back to those. On a device the OS resolves through it
	// while the data plane runs.
	DNS          bool
	DNSUpstreams []netip.AddrPort

	// Host is the data plane's network namespace's; Device, a device's
	// host adapters (required with RouteTable; nil in a server's worker,
	// which then never asks or points the OS's resolvers).
	Host   WorkerHost
	Device *DeviceHost

	// Its connection (required; a worker's is always meant to be up), and
	// a device's (Node.run): where its status goes, its Connect and
	// Disconnect requests, and who hears its events.
	report   *report
	conn     *connection
	requests <-chan connectRequest
	events   emitter
	// Rules are the device's own rule choice (LocalRulesFile), and
	// rulesRequests replace them while it runs.
	Rules         rules.Local
	rulesRequests <-chan rulesRequest

	// tuning is what tests change; production leaves it zero.
	tuning tuning
}

// tuning is the one place a data plane differs in tests: the timing they
// can't wait out and the port they can't bind. A node's data plane gets
// its tuning from Node.tweak. What tests check about a running data plane
// they read from its status and events, not from hooks.
type tuning struct {
	// path is the path layer's timing; retryAfter the delay before a
	// failed start, Apply or listener is retried (0: RetryAfter).
	path       path.Options
	retryAfter time.Duration
	// blobOptions are a worker's blob limits (MaxHeld is always
	// blobs.ServerMaxHeldSize).
	blobOptions blobs.Options
	// dnsPort is the resolver's port (0: 53).
	dnsPort uint16
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
	if dp.tuning.retryAfter == 0 {
		dp.tuning.retryAfter = RetryAfter
	}
	if dp.Log == nil {
		dp.Log = slog.New(slog.DiscardHandler)
	}
	if dp.conn == nil {
		return errors.New("agent: a data plane needs its connection")
	}
	if dp.RouteTable && dp.Device == nil {
		return errors.New("agent: a route table needs a device's host")
	}
	section, err := openSection(dp.Map, dp.Keys)
	if err != nil {
		return err
	}
	r := &runner{
		dp: dp, maps: dp.Maps, conn: dp.conn, guard: &dnsGuard{}, tun: dp.Interface,
		follow: mapFollower{
			log: dp.Log, keys: dp.Keys, report: dp.report, cur: dp.Map, section: section,
			removedMsg: "the data plane stops until a map includes it again",
		},
	}
	if dp.Blobs != nil {
		r.blobsChanged = dp.Blobs.Subscribe()
	}
	// The first map must run: a node that can't carry it shouldn't look
	// up. A shutdown meanwhile is no failure.
	if r.conn.state == connConnecting {
		if err := r.start(ctx); err != nil {
			// The node returns: its connection is down.
			logRefused(r.dp.Log, r.conn.startFailed(false))
			r.publish()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		logRefused(r.dp.Log, r.conn.started())
		r.tell(EventConnected)
	}
	defer r.shutdown()
	if dp.Blobs != nil {
		// Stopped before the data plane, whose TUN its sockets are on.
		bctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); dp.Blobs.Run(bctx) }()
		defer func() { cancel(); <-done }()
	}
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

// runner follows the space's maps (follow) and runs the data plane while
// the node is in the space and its connection is meant to be up.
type runner struct {
	dp   DataPlane
	maps <-chan []byte
	// follow is the map the runner follows (its section, its removals).
	follow mapFollower
	// conn is the device's connection: connected while engine is set.
	conn *connection
	// told are the events to tell once the report shows them (publish);
	// shown is the problems the report showed at the last publish.
	told  []EventKind
	shown struct{ dnsUnprotected, routeTableFailing bool }

	// engine and listeners are nil while stopped: the node was removed,
	// or starting again failed; so are resolver and system, the OS's
	// resolver configuration while it points at the resolver (systemCfg).
	engine    *dataplane.Engine
	listeners *listenerSet
	resolver  *dns.Server
	// routes is the engine's route table in route-table mode (nil
	// otherwise, and while stopped).
	routes *routeTable
	// upstreams are the resolver's direct upstreams as it started.
	upstreams []netip.AddrPort
	// upstreamsUnknown is set while the OS's own resolvers, the direct
	// upstreams, couldn't be read yet (newResolver's read failed): the OS
	// configuration tells them at its first good read
	// (dns.SystemConfig.UpstreamsUnknown), from its own goroutine.
	upstreamsUnknown atomic.Bool
	// tun is the running TUN's name (Interface until one runs).
	tun string
	// guard is the OS's resolver configuration while it should point at
	// the resolver (systemCfg), and why it doesn't; dnsRetryAt is when to
	// try pointing it again.
	guard      *dnsGuard
	systemCfg  dns.SystemConfig
	dnsRetryAt time.Time
	// blobsChanged is signalled when the blob service's lists change.
	blobsChanged <-chan struct{}
	// retryAt is when to retry a failed Apply or start (zero: nothing to
	// retry).
	retryAt time.Time
}

// tunMTU is the TUN's MTU: the overlay's, below the engine's per-link
// MTU (LinkMTU).
const tunMTU = 1420

// start brings the data plane up on the current section. It fails with a
// *StartError, having undone what it set up, last first.
func (r *runner) start(ctx context.Context) error {
	var undo undoStack
	ports, err := r.openPorts(&undo)
	if err != nil {
		undo.run()
		// The route table isn't the data plane's own: a crashed run's
		// would block traffic meanwhile.
		if r.dp.RouteTable {
			r.dp.Device.clearNetwork(r.dp.Log)
		}
		return err
	}
	engine, err := dataplane.NewEngine(r.engineConfig(ports))
	if err != nil {
		undo.run()
		return &StartError{Step: StepEngine, Err: err}
	}
	// The engine owns the TUN, its configurator and the route table now:
	// its Close takes them down.
	undo = undoStack{func() { _ = engine.Close() }}
	if res := ports.resolver; res != nil {
		undo.push(func() { _ = res.Close() })
	}
	if err := engine.Apply(ctx, r.follow.section); err != nil {
		step := engine.Status().LastApplyError
		undo.run()
		return &StartError{Step: step, Err: fmt.Errorf("applying map version %d: %w", r.follow.cur.Header().Version, err)}
	}
	r.engine, r.resolver, r.routes = engine, ports.resolver, ports.routes
	if r.resolver != nil && r.routes != nil {
		if err := r.routes.SetDirectUpstreams(ctx, r.upstreams); err != nil {
			r.dp.Log.Warn("DNS: keeping the direct upstreams reachable failed", "err", path.RedactError(err))
		}
	}
	r.pointSystem()
	r.listeners = newListenerSet(engine, r.dp.Log, r.dp.tuning.retryAfter)
	r.retryAt = time.Time{}
	r.applied()
	return nil
}

// startPorts are what a start opens for its engine; a nil one is what the
// data plane runs without (ifc: tests; routes, resolver: off).
type startPorts struct {
	tun      wgtun.Device
	ifc      netcfg.Configurator
	routes   *routeTable
	resolver *dns.Server
}

// openPorts opens the TUN's configurator, the TUN, the route table and the
// resolver, pushing each one's Close onto undo. It fails with a
// *StartError, never once the route table is open.
func (r *runner) openPorts(undo *undoStack) (startPorts, error) {
	var p startPorts
	ifc, err := r.dp.Host.NewConfigurator(netcfg.OwnerOverlay)
	if err != nil {
		return p, &StartError{Step: StepTUN, Err: err}
	}
	if ifc != nil {
		p.ifc = ifc
		undo.push(func() { _ = ifc.Close() })
	}
	dev, err := r.dp.Host.NewTUN(r.dp.Interface, tunMTU)
	if err != nil {
		return p, &StartError{Step: StepTUN, Err: err}
	}
	p.tun = dev
	undo.push(func() { _ = dev.Close() })
	if name, err := dev.Name(); err == nil && name != "" {
		r.tun = name
	}
	if r.dp.RouteTable {
		rt, err := r.dp.Device.NewRouteTable(r.dp.Log, r.dp.Device.NewGuard())
		if err != nil {
			return p, &StartError{Step: dataplane.StepRouteTable, Err: err}
		}
		routes := newRouteTable(rt)
		p.routes = routes
		undo.push(func() { _ = routes.Close() })
	}
	if r.dp.DNS {
		res := r.newResolver()
		p.resolver = res
		undo.push(func() { _ = res.Close() })
	}
	return p, nil
}

// engineConfig is the engine's configuration on p, for the current map.
// Only the ports p has go in: a nil adapter in a port would look set.
func (r *runner) engineConfig(p startPorts) dataplane.EngineConfig {
	cfg := dataplane.EngineConfig{
		ID:           r.dp.Keys.ID,
		Space:        transport.SpaceID(r.follow.cur.Header().SpaceID),
		WireGuardKey: r.dp.Keys.WireGuard,
		Registry:     r.dp.Registry,
		TUN:          p.tun,
		LinkMTU:      r.dp.LinkMTU,
		Path:         r.dp.tuning.path,
		Log:          r.dp.Log,
		Forward:      r.dp.Forward,
		Rules:        r.dp.Rules,
	}
	if p.ifc != nil {
		cfg.Interface = overlayInterface{p.ifc}
	}
	if p.routes != nil {
		cfg.RouteTable = p.routes
	}
	if p.resolver != nil {
		cfg.DNS = dnsResolver{p.resolver}
	}
	if b := r.dp.Blobs; b != nil {
		// The rules' lists: the current map's once held, the previous
		// version until then. ReloadRules follows the service's changes.
		cfg.Blobs = func(ref netmap.BlobRef) ([]byte, bool) { return b.Get(ref.SHA256) }
		cfg.StandIn = b.Latest
	}
	return cfg
}

// stop takes the data plane down: listeners, engine, TUN and its
// configuration. Callers move the connection (and take the map) first:
// the report gets the whole new state at once, with the engine gone before
// it closes, so a status read meanwhile is never a mix of before and
// after.
func (r *runner) stop() {
	if r.engine == nil {
		// Down with nothing running (a start that failed, a node removed
		// before it ran): what a crashed run left goes now.
		if r.dp.RouteTable {
			r.dp.Device.clearNetwork(r.dp.Log)
		}
		return
	}
	engine, listeners, resolver := r.engine, r.listeners, r.resolver
	r.engine, r.listeners, r.resolver, r.routes = nil, nil, nil, nil
	r.retryAt = time.Time{}
	r.publish()
	r.restoreSystem()
	if resolver != nil {
		_ = resolver.Close()
	}
	listeners.closeAll()
	if err := engine.Close(); err != nil {
		r.dp.Log.Warn("closing the data plane", "err", err)
	}
	listeners.wait()
}

// shutdown takes the data plane down as the node stops: its connection
// goes with it, disconnected (a node's next start reads Config.Connect).
func (r *runner) shutdown() {
	if !r.conn.disconnected() {
		logRefused(r.dp.Log, r.conn.disconnect())
	}
	r.stop()
	r.publish()
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
			r.listeners.reconcile(ctx, r.dp.Inbound.Listeners(r.follow.section))
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
		case <-r.blobsChanged:
			r.reloadRules()
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

// publish puts the data plane's state into the device's report, then
// tells the events that state shows: those queued (tell), in the order
// they were, then the problems the report shows that it didn't before.
func (r *runner) publish() {
	n := 0
	if r.listeners != nil {
		n = len(r.listeners.serving)
	}
	r.dp.report.set(func(p *report) {
		p.engine, p.version, p.removed, p.retrying, p.listeners, p.conn, p.dns =
			r.engine, r.follow.cur.Header().Version, r.follow.removed, !r.retryAt.IsZero(), n, r.conn.state, r.guard.problem
	})
	// What Status says of them (DNSUnprotected; DataPlane.RouteTable's
	// Error): the route table recovers and fails again on its own, the
	// OS's resolver configuration may change what it says.
	dnsUnprotected := r.engine != nil && dns.Unprotected(r.guard.problem())
	routeTableFailing := r.routes != nil && r.routes.Status().Error != ""
	if dnsUnprotected && !r.shown.dnsUnprotected {
		r.tell(EventDNSUnprotected)
	}
	if routeTableFailing && !r.shown.routeTableFailing {
		r.tell(EventRouteTableNotEnforced)
	}
	r.shown.dnsUnprotected, r.shown.routeTableFailing = dnsUnprotected, routeTableFailing
	told := r.told
	r.told = nil
	for _, kind := range told {
		r.dp.events.emit(kind, r.follow.cur.Header().Version)
	}
}

// tell has publish tell kind.
func (r *runner) tell(kind EventKind) { r.told = append(r.told, kind) }

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
	case !connect && !r.conn.disconnected():
		if err := r.conn.disconnect(); err != nil {
			logRefused(r.dp.Log, err)
			return err
		}
		r.stop()
		r.retryAt = time.Time{}
		r.updateBlobs()
		r.dp.Log.Info("disconnected")
	case connect && (r.conn.disconnected() || r.conn.state == connRetrying):
		// Down on purpose, or up but its start failed and waits for a
		// retry: either way it starts now, and says if it can't; out of
		// its space, once a map has it again.
		retry := !r.conn.disconnected()
		if err := r.conn.connect(!r.follow.removed); err != nil {
			logRefused(r.dp.Log, err)
			return err
		}
		if r.conn.state == connRemoved {
			r.dp.Log.Info("connecting once a map includes this node")
			break
		}
		if err := r.start(ctx); err != nil {
			logRefused(r.dp.Log, r.conn.startFailed(retry))
			if retry {
				r.retryAt = time.Now().Add(r.dp.tuning.retryAfter)
			}
			r.dp.Log.Warn("connecting failed", "version", r.follow.cur.Header().Version, "err", err)
			return err
		}
		logRefused(r.dp.Log, r.conn.started())
		r.tell(EventConnected)
		r.dp.Log.Info("connected")
	}
	if connect && r.conn.state == connConnected {
		if err := r.guard.problem(); dns.Unprotected(err) {
			return fmt.Errorf("%w: %v", ErrDNSUnprotected, err)
		}
	}
	return nil
}

// nextRetry is the earliest retry due: the data plane's or a listener's.
func (r *runner) nextRetry() (time.Time, bool) {
	at, ok := r.retryAt, !r.retryAt.IsZero()
	if d := r.dnsRetryAt; !d.IsZero() && (!ok || d.Before(at)) {
		at, ok = d, true
	}
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
	if d := r.dnsRetryAt; !d.IsZero() && !time.Now().Before(d) {
		r.dnsRetryAt = time.Time{}
		if r.engine != nil {
			r.pointSystem()
		}
	}
	if r.retryAt.IsZero() || time.Now().Before(r.retryAt) {
		return
	}
	switch r.conn.state {
	case connRetrying:
		r.tryStart(ctx)
	case connConnected:
		r.apply(ctx)
	}
}

// next takes a newer map, if it is one, and acts on it: a map without the
// node stops the data plane, one with it applies it (or starts the data
// plane on it).
func (r *runner) next(ctx context.Context, envelope []byte) {
	taken, removed, back := r.follow.take(envelope)
	if !taken {
		return
	}
	if back {
		r.follow.sayBack()
		r.tell(EventBackInSpace)
	}
	if removed {
		r.tell(EventRemovedFromSpace)
	}
	if r.follow.removed {
		logRefused(r.dp.Log, r.conn.remove())
		r.stop()
		r.retryAt = time.Time{}
		r.updateBlobs()
		return
	}
	switch r.conn.state {
	case connRemoved, connRetrying:
		r.tryStart(ctx)
	case connConnected:
		r.apply(ctx)
	}
}

// tryStart starts the data plane nobody asked to start (back in its space,
// a retry), and retries it if that fails.
func (r *runner) tryStart(ctx context.Context) {
	if err := r.conn.resume(); err != nil {
		logRefused(r.dp.Log, err)
		return
	}
	if err := r.start(ctx); err != nil {
		logRefused(r.dp.Log, r.conn.startFailed(true))
		r.retryAt = time.Now().Add(r.dp.tuning.retryAfter)
		r.dp.Log.Warn("starting the data plane failed, retrying", "version", r.follow.cur.Header().Version, "in", r.dp.tuning.retryAfter, "err", path.RedactError(err))
		return
	}
	logRefused(r.dp.Log, r.conn.started())
	r.tell(EventConnected)
}

func (r *runner) apply(ctx context.Context) {
	if err := r.engine.Apply(ctx, r.follow.section); err != nil {
		r.retryAt = time.Now().Add(r.dp.tuning.retryAfter)
		r.dp.Log.Warn("applying the map failed, retrying", "version", r.follow.cur.Header().Version,
			"step", r.engine.Status().LastApplyError, "in", r.dp.tuning.retryAfter, "err", path.RedactError(err))
		return
	}
	r.retryAt = time.Time{}
	r.pointSystem()
	r.applied()
}

// reloadRules compiles the rules again with the lists held now.
func (r *runner) reloadRules() {
	if r.engine == nil {
		return
	}
	if err := r.engine.ReloadRules(); err != nil && !errors.Is(err, rules.ErrPresetUnavailable) {
		r.dp.Log.Warn("recompiling the rules with new lists", "err", err)
	}
}

// updateBlobs gives the blob service what the current map asks of it:
// nothing while the data plane is stopped.
func (r *runner) updateBlobs() {
	if r.dp.Blobs == nil {
		return
	}
	if r.engine == nil && r.follow.removed {
		r.dp.Blobs.Update(blobs.Plan{}) // the space's lists are no use now
		return
	}
	if r.engine == nil {
		// Down (disconnected, or a start to retry): the lists stay, on
		// disk too, but nothing is fetched or served.
		p := blobs.PlanFrom(r.follow.cur.Header().Blobs, r.follow.section, false, r.tun, r.dp.ServeBlobs)
		r.dp.Blobs.Update(blobs.Plan{Want: p.Want})
		return
	}
	r.dp.Blobs.Update(blobs.PlanFrom(r.follow.cur.Header().Blobs, r.follow.section, r.engine.Status().IPv6, r.tun, r.dp.ServeBlobs))
}

func (r *runner) applied() {
	r.updateBlobs()
	st := r.engine.Status()
	attrs := []any{"version", r.follow.cur.Header().Version, "node", r.dp.Keys.ID, "ipv4", r.follow.section.Node.IPv4,
		"mtu", st.MTU, "peers", len(st.Peers), "skipped", len(st.Skipped)}
	if st.IPv6 {
		attrs = append(attrs, "ipv6", r.follow.section.Node.IPv6)
	} else {
		attrs = append(attrs, "ipv6_off", st.IPv6Off)
	}
	if n := r.follow.section.Node; n.Kind == netmap.NodeServer {
		attrs = append(attrs, serverSettings(n)...)
		attrs = append(attrs, "exit", onOff(st.Exit))
		if n.AllowEgress && !st.Exit {
			r.dp.Log.Warn("the map allows egress, but a server forwards its space's internet traffic only in server mode: not an exit here")
		}
	}
	if st.RouteTable.Enforced {
		attrs = append(attrs, "route_table_routes", st.RouteTable.Routes)
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
	attrs := []any{"version", r.follow.cur.Header().Version, "peers", len(st.Peers), "handshaken", handshaken,
		"neighbors", len(st.Neighbors), "links_up", up, "listeners", len(r.listeners.serving),
		"no_path", st.Path.NoPath, "no_route", st.Router.NoRoute}
	if r.resolver != nil {
		attrs = append(attrs, "dns", r.resolver.Counters())
	}
	if r.dp.Blobs != nil {
		b := r.dp.Blobs.Status()
		attrs = append(attrs, "blobs_wanted", b.Wanted, "blobs_held", b.Held, "blobs_rejected", b.Rejected+b.StoreRejected)
	}
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
