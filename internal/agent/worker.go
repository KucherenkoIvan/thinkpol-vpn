package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Worker is a server's data plane for one space, as `thinkpol worker`
// serves it inside its sandbox (worker.Run): it waits for the supervisor's
// WorkerConfig, then runs RunDataPlane on its own TUN in its namespace,
// with the supervisor's shared listeners as its inbound, applying each
// newer map the supervisor sends.
func Worker(log *slog.Logger) worker.Serve {
	return func(ctx context.Context, s worker.Session) error {
		var first WorkerConfig
		select {
		case <-ctx.Done():
			return nil
		case b := <-s.Config:
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
		reg, err := Transports()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var badConfig atomic.Pointer[error]
		maps := make(chan []byte, 1)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case b := <-s.Config:
					c, err := DecodeWorkerConfig(b)
					if err == nil && !c.sameNode(first) {
						err = errors.New("the supervisor changed the worker's keys or trust")
					}
					if err != nil {
						badConfig.Store(&err)
						cancel()
						return
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
				case c := <-s.SharedCounters:
					counters.Store(&c)
				}
			}
		}()

		err = RunDataPlane(ctx, DataPlane{
			Keys:      first.Keys,
			Map:       m,
			Maps:      maps,
			Registry:  reg,
			Inbound:   SharedInbound(ctx, reg, s.Listeners),
			Interface: first.Interface,
			LinkMTU:   first.LinkMTU,
			Log:       log,
			// The space's own figures only (TP-041 seals them into its
			// telemetry).
			Status: func() []any {
				d := s.SharedDrops()
				attrs := []any{"shared_queue_full", d.QueueFull, "shared_unknown_listener", d.UnknownListener}
				if c := counters.Load(); c != nil {
					attrs = append(attrs, "shared", *c)
				}
				return attrs
			},
		})
		if bad := badConfig.Load(); bad != nil {
			return *bad
		}
		return err
	}
}
