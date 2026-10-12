//go:build linux && !android

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	shared := newSharedListeners(data)
	defer shared.update(nil) // every listener done
	ch := channels{config: make(chan []byte, 1), listeners: make(chan []SharedListener, 1), counters: make(chan ipc.SharedCounters, 1)}
	seeds := NewSeeds()
	go readControl(control, shared, ch, seeds, cancel)
	go readData(data, shared, cancel)

	err = serve(ctx, Session{
		Space:          space,
		Interface:      init.Interface,
		Addrs:          init.Addrs,
		Gateways:       init.Gateways,
		Config:         ch.config,
		Listeners:      ch.listeners,
		SharedDrops:    shared.drops,
		SharedCounters: ch.counters,
		Seeds:          seeds,
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

// channels are where readControl delivers, latest-wins.
type channels struct {
	config    chan []byte
	listeners chan []SharedListener
	counters  chan ipc.SharedCounters
}

// latest replaces a pending value the serve loop hasn't taken; only the
// control reader sends, so it never blocks.
func latest[T any](ch chan T, v T) {
	select {
	case <-ch:
	default:
	}
	ch <- v
}

// readData dispatches the datagrams the supervisor forwards; EOF is left to
// the control socket, anything malformed ends the worker.
func readData(data *ipc.Conn, shared *sharedListeners, cancel context.CancelCauseFunc) {
	for {
		m, err := data.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				cancel(fmt.Errorf("worker: data socket: %w", err))
			}
			return
		}
		m.CloseFiles()
		if m.Kind != ipc.KindDatagram {
			cancel(fmt.Errorf("worker: unexpected %v message on the data socket", m.Kind))
			return
		}
		if err := shared.datagram(m.Payload); err != nil {
			cancel(fmt.Errorf("worker: %w", err))
			return
		}
	}
}

// readControl delivers each Config and Listeners the supervisor sends
// (latest-wins) and each stream it hands over, and ends the worker on Stop,
// EOF or anything unexpected.
func readControl(control *ipc.Conn, shared *sharedListeners, ch channels, seeds *Seeds, cancel context.CancelCauseFunc) {
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
			latest(ch.config, config)
		case ipc.KindBlob:
			// Held before the next message (the config naming it) is read.
			b, err := readBlob(m)
			if err != nil {
				cancel(fmt.Errorf("worker: blob: %w", err))
				return
			}
			seeds.Add(b)
		case ipc.KindListeners:
			m.CloseFiles()
			ls, err := ipc.DecodeListeners(m)
			if err != nil {
				cancel(fmt.Errorf("worker: %w", err))
				return
			}
			latest(ch.listeners, shared.update(ls))
		case ipc.KindCounters:
			c, err := ipc.DecodeCounters(m)
			if err != nil {
				cancel(fmt.Errorf("worker: %w", err))
				return
			}
			latest(ch.counters, c)
		case ipc.KindStream:
			id, f, consumed, err := ipc.DecodeStream(m)
			if err != nil {
				cancel(fmt.Errorf("worker: %w", err))
				return
			}
			conn, err := net.FileConn(f)
			_ = f.Close()
			if err != nil {
				continue // that connection is lost, the rest goes on
			}
			shared.stream(id, conn, consumed)
		default:
			m.CloseFiles()
			cancel(fmt.Errorf("worker: unexpected %v message", m.Kind))
			return
		}
	}
}

// readConfig returns a config message's payload, reading it from the attached
// sealed memfd when it came that way. A memfd is read from offset 0 for its
// whole size, not from the file's current position (the supervisor wrote it).
func readConfig(m ipc.Message) ([]byte, error) {
	defer m.CloseFiles()
	if len(m.Files) == 0 {
		return m.Payload, nil
	}
	f := m.Files[0]
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.NewSectionReader(f, 0, fi.Size()))
}

// readBlob reads a Blob message's memfd from offset 0, at most
// ipc.MaxBlobSize bytes.
func readBlob(m ipc.Message) ([]byte, error) {
	defer m.CloseFiles()
	if len(m.Files) != 1 {
		return nil, fmt.Errorf("%d files attached", len(m.Files))
	}
	fi, err := m.Files[0].Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() <= 0 || fi.Size() > ipc.MaxBlobSize {
		return nil, fmt.Errorf("a blob of %d bytes", fi.Size())
	}
	return io.ReadAll(io.NewSectionReader(m.Files[0], 0, fi.Size()))
}
