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
	// Maps delivers envelopes of the same space, latest-wins. One is
	// applied only if Map.Next takes it (valid, signed by the space, newer)
	// and the node's section in it opens; otherwise the node keeps running
	// on the map it has.
	Maps     <-chan []byte
	Registry *transport.Registry
	Inbound  Inbound
	// Interface names the TUN (tun.DefaultName when empty).
	Interface string
	// LinkMTU is the MTU of the network under the links
	// (dataplane.DefaultLinkMTU when 0).
	LinkMTU int
	// Log gets the data plane's events. It may quote the map at debug
	// level: keep it local (stderr and the in-memory ring).
	Log *slog.Logger
	// Status, if set, adds attributes to the periodic status line at debug
	// level (a worker's shared-listener figures).
	Status func() []any

	// What tests swap: the TUN and its configurator, the path layer's
	// timing, how long to wait before retrying what failed.
	newTUN     func(name string) (wgtun.Device, netcfg.Configurator, error)
	path       path.Options
	retryAfter time.Duration
}

// RetryAfter is how long a data plane waits before retrying an Apply or a
// listener that failed.
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
	dev, ifc, err := dp.newTUN(dp.Interface)
	if err != nil {
		return err
	}
	engine, err := dataplane.NewEngine(dataplane.EngineConfig{
		ID:           dp.Keys.ID,
		Space:        transport.SpaceID(dp.Map.Header().SpaceID),
		WireGuardKey: dp.Keys.WireGuard,
		Registry:     dp.Registry,
		TUN:          dev,
		Interface:    ifc,
		LinkMTU:      dp.LinkMTU,
		Path:         dp.path,
		Log:          dp.Log,
	})
	if err != nil {
		if ifc != nil {
			_ = ifc.Close()
		}
		_ = dev.Close()
		return err
	}
	r := &runner{dp: dp, engine: engine, cur: dp.Map, section: section, listeners: newListenerSet(engine, dp.Log)}
	defer r.close()
	// The first map must run: a node that can't carry it shouldn't look up.
	if err := engine.Apply(ctx, section); err != nil {
		return fmt.Errorf("applying map version %d: %w", dp.Map.Header().Version, err)
	}
	r.applied()
	return r.loop(ctx)
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

type runner struct {
	dp        DataPlane
	engine    *dataplane.Engine
	cur       *netmap.Map
	section   netmap.Section
	listeners *listenerSet
	// applyFailed is set while the current section's Apply failed and is
	// retried.
	applyFailed bool
}

func (r *runner) loop(ctx context.Context) error {
	var retry <-chan time.Time
	arm := func() {
		if retry == nil && (r.applyFailed || r.listeners.failed) {
			retry = time.After(r.dp.retryAfter)
		}
	}
	status := time.NewTicker(statusEvery)
	defer status.Stop()
	r.listeners.reconcile(ctx, r.dp.Inbound.Listeners(r.section))
	arm()
	for {
		select {
		case <-ctx.Done():
			return nil
		case env := <-r.dp.Maps:
			r.next(ctx, env)
		case <-r.dp.Inbound.Changed():
		case <-r.listeners.ended:
		case <-retry:
			retry = nil
			if r.applyFailed {
				r.apply(ctx)
			}
		case <-status.C:
			r.logStatus()
			continue
		}
		r.listeners.reconcile(ctx, r.dp.Inbound.Listeners(r.section))
		arm()
	}
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
	if err != nil {
		r.dp.Log.Error("map refused, keeping the current one", "version", r.cur.Header().Version, "err", err)
		return
	}
	if section.Node.Kind != r.section.Node.Kind {
		r.dp.Log.Warn("the map changes this node's kind; restart the node to change its mode", "kind", section.Node.Kind)
	}
	r.cur, r.section = m, section
	r.apply(ctx)
}

func (r *runner) apply(ctx context.Context) {
	if err := r.engine.Apply(ctx, r.section); err != nil {
		r.applyFailed = true
		r.dp.Log.Warn("applying the map failed, retrying", "version", r.cur.Header().Version,
			"step", r.engine.Status().LastApplyError, "in", r.dp.retryAfter, "err", err)
		return
	}
	r.applied()
}

func (r *runner) applied() {
	r.applyFailed = false
	st := r.engine.Status()
	attrs := []any{"version", r.cur.Header().Version, "node", r.dp.Keys.ID, "ipv4", r.section.Node.IPv4,
		"mtu", st.MTU, "peers", len(st.Peers), "skipped", len(st.Skipped)}
	if st.IPv6 {
		attrs = append(attrs, "ipv6", r.section.Node.IPv6)
	} else {
		attrs = append(attrs, "ipv6_off", st.IPv6Off)
	}
	r.dp.Log.Info("map applied", attrs...)
}

func (r *runner) logStatus() {
	if !r.dp.Log.Enabled(context.Background(), slog.LevelDebug) {
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
		"neighbors", len(st.Neighbors), "links_up", up, "listeners", r.listeners.running(),
		"no_path", st.Path.NoPath, "no_route", st.Router.NoRoute}
	if r.dp.Status != nil {
		attrs = append(attrs, r.dp.Status()...)
	}
	r.dp.Log.Debug("status", attrs...)
}

func (r *runner) close() {
	r.listeners.closeAll()
	if err := r.engine.Close(); err != nil {
		r.dp.Log.Warn("closing the data plane", "err", err)
	}
	r.listeners.wait()
}

// listenerSet is what a data plane serves of its Inbound's listeners.
type listenerSet struct {
	engine *dataplane.Engine
	log    *slog.Logger
	// ended is signalled when a listener's Serve returned on its own.
	ended   chan struct{}
	serving map[string]*served
	// failed is set while a listener that should run doesn't.
	failed bool
}

type served struct {
	l      transport.Listener
	closed atomic.Bool // by the set
	done   chan struct{}
}

func newListenerSet(engine *dataplane.Engine, log *slog.Logger) *listenerSet {
	return &listenerSet{engine: engine, log: log, ended: make(chan struct{}, 1), serving: map[string]*served{}}
}

// reconcile closes the listeners not in want (or ended) and opens those in
// want that don't run.
func (ls *listenerSet) reconcile(ctx context.Context, want []Listener) {
	keep := make(map[string]bool, len(want))
	for _, l := range want {
		keep[l.Key] = true
	}
	for key, s := range ls.serving {
		select {
		case <-s.done:
			delete(ls.serving, key)
			continue
		default:
		}
		if !keep[key] {
			s.closed.Store(true)
			_ = s.l.Close()
			<-s.done
			delete(ls.serving, key)
			ls.log.Info("listener closed", "listener", key)
		}
	}
	ls.failed = false
	for _, l := range want {
		if ls.serving[l.Key] != nil || isClosed(l.Done) {
			continue
		}
		lst, err := l.Open(ctx, ls.engine.Inbound(l.Transport))
		if err != nil {
			ls.failed = true
			ls.log.Warn("opening a listener failed, retrying", "listener", l.Key, "err", err)
			continue
		}
		s := &served{l: lst, done: make(chan struct{})}
		ls.serving[l.Key] = s
		ls.log.Info("listening", "listener", l.Key, "address", lst.Addr())
		go func() {
			defer close(s.done)
			err := ls.engine.Serve(l.Transport, lst)
			if s.closed.Load() || isClosed(l.Done) {
				return
			}
			ls.log.Warn("listener stopped", "listener", l.Key, "err", err)
			select {
			case ls.ended <- struct{}{}:
			default:
			}
		}()
	}
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

func (ls *listenerSet) running() int { return len(ls.serving) }

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
