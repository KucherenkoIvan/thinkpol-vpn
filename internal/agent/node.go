package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/KucherenkoIvan/go-kernel/app"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
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
}

// Prepare reads and checks what a node runs from (LoadState) and decides
// its mode: a node whose map is invalid, or holds no section for its keys,
// never starts.
func Prepare(cfg Config, logs Logs) (*Node, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
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
	n := &Node{cfg: cfg, state: st, mode: cfg.Mode, logs: logs}
	if n.mode == ModeAuto {
		n.mode = ModeDevice
		if st.Section.Node.Kind == netmap.NodeServer {
			n.mode = ModeServer
		}
	}
	return n, nil
}

// Mode is the mode the node runs in.
func (n *Node) Mode() Mode { return n.mode }

// State is what the node runs from.
func (n *Node) State() State { return n.state }

// Run runs the node until ctx ends or it fails, and undoes everything it
// set up before returning: a clean stop (nil) leaves no interface, route,
// namespace or nftables table behind. reload (SIGHUP) makes it read the
// map file at once. On a host whose data plane isn't there yet it refuses
// before changing anything.
func (n *Node) Run(ctx context.Context, reload <-chan os.Signal) error {
	if err := supported(); err != nil {
		return err
	}
	h := n.state.Map.Header()
	n.logs.Info("starting", "mode", n.mode, "space", h.SpaceID, "node", n.state.Keys.ID, "version", h.Version, "map", n.state.MapPath)
	watcher := &mapWatcher{path: n.state.MapPath, interval: n.cfg.MapPoll, reload: reload, log: n.logs.Logger, last: n.state.mapFile}
	maps := make(chan []byte, 1)
	reg, err := Transports()
	if err != nil {
		return err
	}
	if n.mode == ModeServer {
		return n.runServer(ctx, reg, watcher, maps)
	}
	return app.Run(ctx,
		app.Adapter{Name: "map watcher", Run: func(ctx context.Context) error { return watcher.run(ctx, maps) }},
		app.Adapter{Name: "data plane", Run: func(ctx context.Context) error {
			return RunDataPlane(ctx, DataPlane{
				Keys:      n.state.Keys,
				Map:       n.state.Map,
				Maps:      maps,
				Registry:  reg,
				Inbound:   DirectInbound(reg),
				Interface: n.cfg.Interface,
				LinkMTU:   n.cfg.LinkMTU,
				Log:       n.logs.With("space", h.SpaceID.String()),
			})
		}},
	)
}

// runServer runs the supervisor, and gives it the node's space (its
// worker's config and inbound links) and the node's listeners from every
// map.
func (n *Node) runServer(ctx context.Context, reg *transport.Registry, watcher *mapWatcher, maps chan []byte) error {
	level, _ := ParseLevel(n.cfg.LogLevel)
	sup, err := supervisor.New(supervisor.Options{
		Transports: reg,
		Log:        n.logs.With("component", "supervisor"),
		// Workers log at the node's level; their output goes to their
		// space's ring and into the node's log stream.
		Env:    []string{"THINKPOL_LOG_LEVEL=" + level.String()},
		Output: (&workerOutput{w: logOutput(n.logs)}).forSpace,
	})
	if err != nil {
		return err
	}
	s := &serverSpaces{node: n, sup: sup, reg: reg, cur: n.state.Map, section: n.state.Section}
	if err := s.apply(); err != nil {
		_ = sup.Close()
		return err
	}
	return app.Run(ctx,
		app.Adapter{Name: "supervisor", Close: func(context.Context) error { return sup.Close() }},
		app.Adapter{Name: "map watcher", Run: func(ctx context.Context) error { return watcher.run(ctx, maps) }},
		app.Adapter{Name: "spaces", Run: func(ctx context.Context) error { return s.run(ctx, maps) }},
	)
}

// serverSpaces keeps the supervisor serving the node's current map.
type serverSpaces struct {
	node    *Node
	sup     *supervisor.Supervisor
	reg     *transport.Registry
	cur     *netmap.Map
	section netmap.Section
}

// apply gives the supervisor the current map: the space (whose worker
// gets the map and keys) and the listeners. Only the node owner's space is
// served until hosting grants (TP-040) add guests.
func (s *serverSpaces) apply() error {
	n := s.node
	id := s.cur.Header().SpaceID
	config, err := WorkerConfig{
		Keys: n.state.Keys, Trust: n.state.Trust, Map: s.cur.Bytes(),
		Interface: n.cfg.Interface, LinkMTU: n.cfg.LinkMTU,
	}.Encode()
	if err != nil {
		return err
	}
	inbound := dataplane.AcceptedInbound(s.section, s.reg, transport.SpaceID(id), n.cfg.LinkMTU)
	if err := s.sup.SetSpaces([]supervisor.Space{{ID: id, Config: config, Inbound: inbound.Links}}); err != nil {
		return fmt.Errorf("serving space %v: %w", id, err)
	}
	ls := make([]supervisor.Listener, 0, len(s.section.Node.Listeners))
	for _, l := range s.section.Node.Listeners {
		ls = append(ls, supervisor.Listener{Transport: l.Transport, Address: l.Address.String(), Settings: l.Settings})
	}
	if err := s.sup.SetListeners(ls); err != nil {
		// The others are served; the failed ones are retried.
		return errListeners{err}
	}
	n.logs.Info("map applied", "version", s.cur.Header().Version, "listeners", len(ls), "inbound_skipped", len(inbound.Skipped))
	return nil
}

type errListeners struct{ error }

func (e errListeners) Unwrap() error { return e.error }

func (s *serverSpaces) run(ctx context.Context, maps <-chan []byte) error {
	log := s.node.logs
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-retry:
			retry = nil
		case env := <-maps:
			m, err := s.cur.Next(env)
			if errors.Is(err, netmap.ErrNotNewer) {
				log.Debug("map not newer, ignored", "version", s.cur.Header().Version)
				continue
			}
			if err != nil {
				log.Warn("map refused, keeping the current one", "version", s.cur.Header().Version, "err", err)
				continue
			}
			section, err := openSection(m, s.node.state.Keys)
			if err != nil {
				log.Error("map refused, keeping the current one", "version", s.cur.Header().Version, "err", err)
				continue
			}
			s.cur, s.section = m, section
		}
		if err := s.apply(); err != nil {
			log.Warn("serving the map failed, retrying", "version", s.cur.Header().Version, "in", RetryAfter, "err", err)
			retry = time.After(RetryAfter)
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
