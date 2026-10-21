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
		var first WorkerConfig
		select {
		case <-ctx.Done():
			return nil
		case b, ok := <-s.Config:
			if !ok {
				return errors.New("the supervisor sent no config")
			}
			c, err := DecodeWorkerConfig(b)
			if err != nil {
				return err
			}
			first = c
		}
		if first.Trust.SpaceID != s.Space {
			return fmt.Errorf("config for space %v sent to the worker of space %v", first.Trust.SpaceID, s.Space)
		}
		m, err := netmap.Verify(first.Map, first.Trust)
		if err != nil {
			return fmt.Errorf("the supervisor's map: %w", err)
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
			for {
				select {
				case <-ctx.Done():
					return
				case b, ok := <-s.Config:
					if !ok {
						return
					}
					c, err := DecodeWorkerConfig(b)
					if err == nil && !c.sameNode(first) {
						err = errors.New("the supervisor changed the worker's keys or trust")
					}
					if err != nil {
						badConfig.Store(&err)
						cancel()
						return
					}
					// Seeds the new map doesn't name go; the ones it
					// names came ahead of this config.
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
		}()
		var counters atomic.Pointer[ipc.SharedCounters]
		go func() {
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
		}()

		dp := base
		dp.Keys, dp.Map, dp.Maps, dp.Registry = first.Keys, m, maps, reg
		dp.Inbound = SharedInbound(ctx, reg, s.Listeners)
		dp.Interface, dp.LinkMTU, dp.Log = first.Interface, first.LinkMTU, log
		// The worker's namespace forwards and SNATs, and the supervisor's
		// tables confine it, so a server allowing egress is an exit here.
		dp.Forward = true
		bo := base.tuning.blobOptions
		bo.Store, bo.Log, bo.Limits.MaxHeld = seedStore{seeds}, log, blobs.ServerMaxHeldSize
		dp.Blobs, dp.ServeBlobs = blobs.NewOnNet(bo, base.Host.BlobNet), true
		dp.DNS, dp.DNSUpstreams = first.DNS, first.DNSUpstreams
		// The space's own figures only (TP-041 seals them into its
		// telemetry).
		dp.StatusAttrs = func() []any {
			var attrs []any
			if s.SharedDrops != nil {
				d := s.SharedDrops()
				attrs = append(attrs, "shared_queue_full", d.QueueFull, "shared_unknown_listener", d.UnknownListener)
			}
			if c := counters.Load(); c != nil {
				attrs = append(attrs, "shared", *c)
			}
			return attrs
		}
		conn := newConnection(true, false) // a worker's: always meant to be up
		dp.conn = &conn
		err = RunDataPlane(ctx, dp)
		if bad := badConfig.Load(); bad != nil {
			return *bad
		}
		return err
	}
}

// retainSeeds drops the seeds m's header doesn't list.
func retainSeeds(seeds *worker.Seeds, m *netmap.Map) {
	listed := map[[32]byte]bool{}
	for _, ref := range m.Header().Blobs {
		listed[ref.SHA256] = true
	}
	seeds.Retain(func(sha [32]byte) bool { return listed[sha] })
}
