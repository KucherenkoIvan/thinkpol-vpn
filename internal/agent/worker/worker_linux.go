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

// Run is a worker's whole life: it takes the supervisor's control and data
// sockets (ipc.ControlFD, ipc.DataFD), waits for Init, sandboxes itself,
// reports Ready, then runs serve, delivering each Config the supervisor
// sends, until the supervisor says Stop (nil) or goes away, ctx ends, or
// serve returns.
func Run(ctx context.Context, space netmap.SpaceID, serve Serve) error {
	control, err := connFromFD(ipc.ControlFD, "control")
	if err != nil {
		return err
	}
	defer func() { _ = control.Close() }()
	data, err := connFromFD(ipc.DataFD, "data")
	if err != nil {
		return err
	}
	defer func() { _ = data.Close() }()

	m, err := control.Receive()
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
	if err := control.Send(ipc.Message{Kind: ipc.KindReady}); err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	configCh := make(chan []byte, 1)
	go readControl(control, configCh, cancel)

	err = serve(ctx, Session{
		Space:     space,
		Interface: init.Interface,
		Addrs:     init.Addrs,
		Gateways:  init.Gateways,
		Config:    configCh,
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

func connFromFD(fd int, name string) (*ipc.Conn, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, fmt.Errorf("worker: no %s socket", name)
	}
	conn, err := ipc.FromFile(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("worker: %s socket: %w", name, err)
	}
	return conn, nil
}

// readControl delivers each Config the supervisor sends (latest-wins) and
// ends the worker on Stop, EOF or anything unexpected.
func readControl(control *ipc.Conn, configCh chan []byte, cancel context.CancelCauseFunc) {
	for {
		m, err := control.Receive()
		switch {
		case errors.Is(err, io.EOF):
			cancel(errSupervisorGone)
			return
		case err != nil:
			cancel(err)
			return
		}
		switch m.Kind {
		case ipc.KindStop:
			m.CloseFiles()
			cancel(errStopped)
			return
		case ipc.KindConfig:
			config, err := readConfig(m)
			if err != nil {
				cancel(fmt.Errorf("worker: config: %w", err))
				return
			}
			// Latest-wins: drop a pending config the serve loop hasn't taken.
			select {
			case <-configCh:
			default:
			}
			configCh <- config
		default:
			m.CloseFiles()
			cancel(fmt.Errorf("worker: unexpected %v message", m.Kind))
			return
		}
	}
}

// readConfig returns a config message's payload, reading it from the attached
// sealed memfd when it came that way.
func readConfig(m ipc.Message) ([]byte, error) {
	defer m.CloseFiles()
	if len(m.Files) == 0 {
		return m.Payload, nil
	}
	return io.ReadAll(m.Files[0])
}
