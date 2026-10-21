package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// ServeSpace is a server's data plane for one space in its worker: it
// waits for the supervisor's WorkerConfig, then runs RunDataPlane on its
// own TUN with the supervisor's shared listeners as its inbound, applying
// each newer map the supervisor sends. Of h it takes only what a worker
// uses (workerHost).
func ServeSpace(log *slog.Logger, h Host) worker.Serve {
	return serveSpace(log, DataPlane{Host: workerHost(h)})
}

// workerHost is what a worker's data plane may use of h: its namespace's
// network configuration and TUN, the transports and the blob network.
// The device-only adapters (the route table and its leak guard, clearing
// a crashed run's routes, the OS's resolvers and their configuration)
// stay out, so a worker can't reach them whatever its flags say.
func workerHost(h Host) Host {
	return Host{NewConfigurator: h.NewConfigurator, NewTUN: h.NewTUN, Transports: h.Transports, BlobNet: h.BlobNet}
}

// serveSpace is ServeSpace on base: its Host and private fields are kept,
// the rest comes from the supervisor.
func serveSpace(log *slog.Logger, base DataPlane) worker.Serve {
	return func(ctx context.Context, s worker.Session) error {
		first, m, err := firstConfig(ctx, s)
		if err != nil || m == nil {
			return err
		}
		reg, err := base.Host.Transports(false)
		if err != nil {
			return err
		}
		seeds := s.Seeds
		if seeds == nil {
			seeds = worker.NewSeeds()
		}
		retainSeeds(seeds, m)

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var badConfig atomic.Pointer[error]
		maps := make(chan []byte, 1)
		go func() {
			if err := followConfigs(ctx, s, first, seeds, maps); err != nil {
				badConfig.Store(&err)
				cancel()
			}
		}()
		var counters atomic.Pointer[ipc.SharedCounters]
		go followCounters(ctx, s, &counters)

		dp := workerDataPlane(base, first, log, seeds)
		dp.Map, dp.Maps, dp.Registry = m, maps, reg
		dp.Inbound = SharedInbound(ctx, reg, s.Listeners)
		// The space's own figures only (TP-041 seals them into its
		// telemetry).
		dp.StatusAttrs = func() []any { return sharedAttrs(s, counters.Load()) }
		err = RunDataPlane(ctx, dp)
		if bad := badConfig.Load(); bad != nil {
			return *bad
		}
		return err
	}
}

// firstConfig waits for the supervisor's first WorkerConfig and checks it
// is for the worker's space, with a map the space signed; a nil map with
// no error is ctx ending first.
func firstConfig(ctx context.Context, s worker.Session) (WorkerConfig, *netmap.Map, error) {
	var first WorkerConfig
	select {
	case <-ctx.Done():
		return first, nil, nil
	case b, ok := <-s.Config:
		if !ok {
			return first, nil, errors.New("the supervisor sent no config")
		}
		c, err := DecodeWorkerConfig(b)
		if err != nil {
			return first, nil, err
		}
		first = c
	}
	if first.Trust.SpaceID != s.Space {
		return first, nil, fmt.Errorf("config for space %v sent to the worker of space %v", first.Trust.SpaceID, s.Space)
	}
	m, err := netmap.Verify(first.Map, first.Trust)
	if err != nil {
		return first, nil, fmt.Errorf("the supervisor's map: %w", err)
	}
	return first, m, nil
}

// followConfigs passes each later config's map to maps, latest-wins, until
// ctx ends or the configs do; a config that doesn't decode, or changes the
// worker's keys or trust, is its error.
func followConfigs(ctx context.Context, s worker.Session, first WorkerConfig, seeds *worker.Seeds, maps chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case b, ok := <-s.Config:
			if !ok {
				return nil
			}
			c, err := DecodeWorkerConfig(b)
			if err == nil && !c.sameNode(first) {
				err = errors.New("the supervisor changed the worker's keys or trust")
			}
			if err != nil {
				return err
			}
			// Seeds the new map doesn't name go; the ones it names came
			// ahead of this config.
			if next, err := netmap.Verify(c.Map, first.Trust); err == nil {
				retainSeeds(seeds, next)
			}
			select {
			case <-maps:
			default:
			}
			maps <- c.Map
		}
	}
}

// followCounters keeps the supervisor's latest shared-listener counters
// for the space in counters, until ctx ends or they do.
func followCounters(ctx context.Context, s worker.Session, counters *atomic.Pointer[ipc.SharedCounters]) {
	for {
		select {
		case <-ctx.Done():
			return
		case c, ok := <-s.SharedCounters:
			if !ok {
				return
			}
			counters.Store(&c)
		}
	}
}

// sharedAttrs are the space's shared-listener figures for its status
// line: the session's drops and the supervisor's counters (nil: none
// yet).
func sharedAttrs(s worker.Session, counters *ipc.SharedCounters) []any {
	var attrs []any
	if s.SharedDrops != nil {
		d := s.SharedDrops()
		attrs = append(attrs, "shared_queue_full", d.QueueFull, "shared_unknown_listener", d.UnknownListener)
	}
	if counters != nil {
		attrs = append(attrs, "shared", *counters)
	}
	return attrs
}

// workerDataPlane is base as a worker's data plane on first: its keys,
// interface, resolver and blobs (served from seeds), an exit when its
// section allows egress, always meant to be up.
func workerDataPlane(base DataPlane, first WorkerConfig, log *slog.Logger, seeds *worker.Seeds) DataPlane {
	dp := base
	dp.Keys = first.Keys
	dp.Interface, dp.LinkMTU, dp.Log = first.Interface, first.LinkMTU, log
	// The worker's namespace forwards and SNATs, and the supervisor's
	// tables confine it, so a server allowing egress is an exit here.
	dp.Forward = true
	bo := base.tuning.blobOptions
	bo.Store, bo.Log, bo.Limits.MaxHeld = seedStore{seeds}, log, blobs.ServerMaxHeldSize
	dp.Blobs, dp.ServeBlobs = blobs.NewOnNet(bo, base.Host.BlobNet), true
	dp.DNS, dp.DNSUpstreams = first.DNS, first.DNSUpstreams
	conn := newConnection(true, false) // a worker's: always meant to be up
	dp.conn = &conn
	return dp
}

// retainSeeds drops the seeds m's header doesn't list.
func retainSeeds(seeds *worker.Seeds, m *netmap.Map) {
	listed := map[[32]byte]bool{}
	for _, ref := range m.Header().Blobs {
		listed[ref.SHA256] = true
	}
	seeds.Retain(func(sha [32]byte) bool { return listed[sha] })
}
