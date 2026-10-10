//go:build linux && !android

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var (
	errStopped        = errors.New("worker: stopped by the supervisor")
	errSupervisorGone = errors.New("worker: the supervisor is gone")
)

// Run is a worker's whole life: it takes the supervisor's socket at
// ipc.WorkerFD, waits for Init, sandboxes itself, reports Ready and runs
// serve until the supervisor says Stop (nil) or goes away, ctx ends, or
// serve returns.
func Run(ctx context.Context, space netmap.SpaceID, serve Serve) error {
	// The sandbox mounts over /proc, /sys and /run: only ever in the
	// namespaces the supervisor made, where the worker is PID 1.
	if os.Getpid() != 1 {
		return errors.New("worker: not started by a supervisor (not PID 1 of its own namespace)")
	}
	f := os.NewFile(ipc.WorkerFD, "supervisor")
	if f == nil {
		return errors.New("worker: no supervisor socket")
	}
	conn, err := ipc.FromFile(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("worker: supervisor socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	m, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("worker: waiting for init: %w", err)
	}
	m.CloseFiles()
	init, err := ipc.DecodeInit(m)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	if init.Space != space.String() {
		return fmt.Errorf("worker: started for space %s, initialized for %s", space, init.Space)
	}
	if err := sandbox(init); err != nil {
		return fmt.Errorf("worker: sandbox: %w", err)
	}
	if err := conn.Send(ipc.Message{Kind: ipc.KindReady}); err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// Until the handoff (TP-010) adds its kinds, Stop is the only message
	// after Init; anything else ends the worker too.
	go func() {
		m, err := conn.Receive()
		switch {
		case errors.Is(err, io.EOF):
			cancel(errSupervisorGone)
		case err != nil:
			cancel(err)
		case m.Kind == ipc.KindStop:
			cancel(errStopped)
		default:
			m.CloseFiles()
			cancel(fmt.Errorf("worker: unexpected %v message", m.Kind))
		}
	}()

	err = serve(ctx, Session{
		Space:     space,
		Interface: init.Interface,
		Addrs:     init.Addrs,
		Gateways:  init.Gateways,
	})
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errStopped):
		return nil
	case err != nil:
		return fmt.Errorf("worker: %w", err)
	case cause != nil:
		return cause
	}
	return errors.New("worker: the data plane stopped on its own")
}
