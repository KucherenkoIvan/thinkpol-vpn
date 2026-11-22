//go:build linux && !android

package supervisor

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// session is one worker process and its sockets, from the Init message to
// the event loop that keeps it current.
type session struct {
	sup     *Supervisor
	w       *worker
	p       *process
	control *ipc.Conn
	data    *ipc.Conn
	// ws is the process's sockets as the shared listeners route to them,
	// with the listeners it acknowledged.
	ws    *workerSockets
	log   *slog.Logger
	ready chan error // the worker's Ready
	gone  chan error // anything on the control socket after Ready
	// sentSeeds are the seeds the current process has had.
	sentSeeds map[[32]byte]bool
	// listenersSent and listenersAcked count the Listeners messages sent
	// and acknowledged: the worker answers each, in order.
	listenersSent  int64
	listenersAcked atomic.Int64
}

// newSession starts a session for the worker's process p, its sockets
// open.
func newSession(sup *Supervisor, w *worker, p *process, control, data *ipc.Conn, log *slog.Logger) *session {
	return &session{
		sup: sup, w: w, p: p, control: control, data: data, log: log,
		ws:    &workerSockets{data: data, control: control},
		ready: make(chan error, 1), gone: make(chan error, 1),
		sentSeeds: map[[32]byte]bool{},
	}
}

// awaitReady sends the worker its Init message and waits for its Ready
// message (WorkerInfo.Ready waits for the listeners too: serve): a
// read or protocol failure or the process's own exit end it before it is
// ready, the ready timeout ends it after; a worker being stopped while not
// yet ready is simply torn down (stopped, no error).
func (sn *session) awaitReady() (stopped bool, err error) {
	init, err := ipc.InitMessage(ipc.Init{
		Space:     sn.w.space.String(),
		Interface: SpaceInterface,
		Addrs:     sn.w.transit.space[:],
		Gateways:  []netip.Addr{sn.w.transit.root[0].Addr(), sn.w.transit.root[1].Addr()},
		UID:       sn.w.uid,
		GID:       sn.w.uid,
		PidsMax:   sn.sup.opts.PidsMax,
	})
	if err != nil {
		return false, err
	}
	if err := sn.control.Send(init); err != nil {
		return false, err
	}
	go readControl(sn.control, sn.ready, sn.gone, func(ids []uint32) {
		sn.sup.shared.acknowledged(sn.ws, ids)
		sn.listenersAcked.Add(1)
	})
	timer := time.NewTimer(sn.sup.opts.ReadyTimeout)
	defer timer.Stop()
	select {
	case err := <-sn.ready:
		if err != nil {
			return false, fmt.Errorf("before ready: %w", err)
		}
	case <-sn.p.gone:
		return false, fmt.Errorf("before ready: %w", sn.p.exit())
	case <-timer.C:
		return false, fmt.Errorf("not ready after %v", sn.sup.opts.ReadyTimeout)
	case <-sn.w.ctx.Done():
		return true, nil
	}
	return false, nil
}

// routed marks the worker ready (WorkerInfo.Ready): sandboxed, and the
// shared listeners route to it.
func (sn *session) routed() {
	sn.w.mu.Lock()
	sn.w.ready = true
	sn.w.readyAt = sn.sup.opts.now()
	sn.w.mu.Unlock()
	sn.log.Info("worker ready")
}

// serve is one ready worker process's event loop, until it stops or ends:
// it keeps the listeners, the seeds and the config current, forwards the
// shared listeners' counters, follows the space's egress and sends the
// stop. It returns why the process ended: nil only when it exited cleanly
// after Stop.
func (sn *session) serve() error {
	// The listeners and the current config once, then whenever they
	// change; datagrams and connections once the worker has acknowledged
	// every listener (attachKnowing), which it must within StopTimeout.
	if err := sn.sendInitial(); err != nil {
		return err
	}
	countersTick := time.NewTicker(sn.sup.opts.CountersInterval)
	defer countersTick.Stop()
	detach := func() {}
	defer func() { detach() }()
	attached := false
	var acked <-chan struct{}
	ackTimer := time.NewTimer(sn.sup.opts.StopTimeout)
	defer ackTimer.Stop()
	ackTimeout := ackTimer.C
	dataGone := make(chan error, 1)
	go sn.readReplies(dataGone)
	for {
		if !attached {
			acked = sn.sup.shared.changes()
			if d, ok := sn.sup.shared.attachKnowing(transport.SpaceID(sn.w.space), sn.ws); ok {
				detach, attached, acked, ackTimeout = d, true, nil, nil
				sn.routed()
			}
		}
		select {
		case <-acked:
		case <-ackTimeout:
			if sn.listenersAcked.Load() < sn.listenersSent {
				_ = sn.control.Close()
				sn.p.kill()
				return exitWith(ExitUnresponsive, fmt.Errorf("listeners not acknowledged: %w", os.ErrDeadlineExceeded))
			}
			// Every one answered, the set moved on since: the change's
			// signal sends it again.
			ackTimer.Reset(sn.sup.opts.StopTimeout)
		case <-sn.p.gone:
			return sn.p.exit()
		case err := <-dataGone:
			if errors.Is(err, io.EOF) {
				continue // the control socket or the exit tells why
			}
			_ = sn.control.Close()
			sn.sup.awaitExit(sn.p)
			return exitWith(ExitProtocolError, fmt.Errorf("data socket: %w", err))
		case <-sn.w.listenersChanged:
			if err := sn.sendListeners(); err != nil {
				return sn.stuck("listeners", err)
			}
		case <-countersTick.C:
			// For the worker's telemetry; skipped when the socket is full.
			if m, err := ipc.CountersMessage(sn.sup.shared.counters(transport.SpaceID(sn.w.space))); err == nil {
				_ = sn.control.TrySend(m)
			}
		case err := <-sn.gone:
			if errors.Is(err, io.EOF) {
				// The worker's control socket closed: it has exited or is
				// exiting, so its own exit is the reason.
				sn.sup.awaitExit(sn.p)
				return sn.p.exit()
			}
			// A protocol break while the worker is still running: that is the
			// reason, whatever its incidental exit code.
			_ = sn.control.Close()
			sn.sup.awaitExit(sn.p)
			return exitWith(ExitProtocolError, fmt.Errorf("socket: %w", err))
		case <-sn.w.notify:
			if err := sn.sendSeeds(); err != nil {
				return sn.stuck("blob seeds", err)
			}
			if err := sn.sendConfig(); err != nil {
				return sn.stuck("config", err)
			}
		case <-sn.w.egressChanged:
			// The root namespace's tables already follow the new egress,
			// whatever this one does; a failure is retried with the next
			// change, or in a fresh namespace.
			if err := applySpaceTable(sn.p.netns, sn.w.transit, sn.sup.currentSpaceEgress(sn.w)); err != nil {
				sn.log.Error("the space's egress table", "err", err)
			}
		case <-sn.w.ctx.Done():
			return sn.stop()
		}
	}
}

// sendInitial sends what a fresh worker needs first: the listeners, the
// seeds its config names, and the config.
func (sn *session) sendInitial() error {
	for _, step := range []struct {
		what string
		send func() error
	}{
		{"listeners", sn.sendListeners},
		{"blob seeds", sn.sendSeeds},
		{"config", sn.sendConfig},
	} {
		if err := step.send(); err != nil {
			return sn.stuck(step.what, err)
		}
	}
	return nil
}

// stop tells the worker to stop and waits for it to, killing it at the
// stop timeout. It returns why the process ended: nil when it exited
// cleanly within the timeout.
func (sn *session) stop() error {
	if err := sn.control.SendTimeout(ipc.Message{Kind: ipc.KindStop}, sn.sup.opts.StopTimeout); err != nil {
		sn.log.Warn("sending stop", "err", err)
		sn.p.kill()
		return exitWith(ExitKilled, fmt.Errorf("killed: %w", err))
	}
	if !sn.sup.awaitExit(sn.p) {
		return exitWith(ExitKilled, fmt.Errorf("killed: still running %v after stop", sn.sup.opts.StopTimeout))
	}
	return sn.p.err
}

// stuck is what a control send that can't finish within StopTimeout means:
// the worker stopped reading its socket, so it is killed (and restarted)
// rather than hold up SetSpaces, SetListeners or Close. Anything else is
// the worker's own exit, the reason.
func (sn *session) stuck(what string, err error) error {
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		sn.sup.awaitExit(sn.p)
		return sn.p.exit()
	}
	_ = sn.control.Close()
	sn.p.kill()
	return exitWith(ExitUnresponsive, fmt.Errorf("sending %s: %w", what, err))
}

// sendListeners tells a worker which shared listeners it is forwarded from.
func (sn *session) sendListeners() error {
	m, err := ipc.ListenersMessage(sn.sup.shared.ipcListeners(transport.SpaceID(sn.w.space)))
	if err != nil {
		return err
	}
	if err := sn.control.SendTimeout(m, sn.sup.opts.StopTimeout); err != nil {
		return err
	}
	sn.listenersSent++
	return nil
}

// sendSeeds sends the worker each of its space's current seeds it hasn't
// had, one sealed memfd per seed; nothing of them is kept here.
func (sn *session) sendSeeds() error {
	seeds := sn.w.currentSeeds()
	if seeds == nil {
		return nil
	}
	for _, b := range seeds() {
		sum := sha256.Sum256(b)
		if sn.sentSeeds[sum] || len(b) == 0 || len(b) > ipc.MaxBlobSize {
			continue
		}
		f, err := sealedMemfd("thinkpol-blob", b)
		if err != nil {
			return err
		}
		err = sn.control.SendTimeout(ipc.Message{Kind: ipc.KindBlob, Files: []*os.File{f}}, sn.sup.opts.StopTimeout)
		_ = f.Close()
		if err != nil {
			return err
		}
		sn.sentSeeds[sum] = true
	}
	return nil
}

// sendConfig sends the worker's current configuration, as a sealed memfd
// when it is too large for one packet.
func (sn *session) sendConfig() error {
	config := sn.w.currentConfig()
	if len(config) == 0 {
		return nil
	}
	if 1+len(config) <= ipc.MaxMessageSize {
		return sn.control.SendTimeout(ipc.ConfigMessage(config), sn.sup.opts.StopTimeout)
	}
	f, err := sealedMemfd("thinkpol-config", config)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return sn.control.SendTimeout(ipc.Message{Kind: ipc.KindConfig, Files: []*os.File{f}}, sn.sup.opts.StopTimeout)
}

// readReplies sends out the datagrams the worker writes to its data
// socket, until the socket closes or the worker breaks the protocol
// (reported on gone; io.EOF when it closed).
func (sn *session) readReplies(gone chan<- error) {
	for {
		m, err := sn.data.Receive()
		if err != nil {
			gone <- err
			return
		}
		m.CloseFiles()
		if m.Kind != ipc.KindDatagram {
			gone <- fmt.Errorf("unexpected %v message", m.Kind)
			return
		}
		h, d, err := ipc.ParseDatagram(m.Payload)
		if err != nil {
			gone <- err
			return
		}
		sn.sup.shared.reply(transport.SpaceID(sn.w.space), h, d)
	}
}

// readControl reports the worker's Ready on ready, then passes each
// ListenersKnown to known, and reports anything else on gone (a protocol
// error, EOF included).
func readControl(conn *ipc.Conn, ready, gone chan<- error, known func([]uint32)) {
	m, err := conn.Receive()
	if err == nil && m.Kind != ipc.KindReady {
		m.CloseFiles()
		err = fmt.Errorf("unexpected %v message", m.Kind)
	}
	ready <- err
	if err != nil {
		return
	}
	for {
		m, err = conn.Receive()
		if err != nil {
			break
		}
		m.CloseFiles()
		if m.Kind != ipc.KindListenersKnown {
			err = fmt.Errorf("unexpected %v message", m.Kind)
			break
		}
		var ids []uint32
		if ids, err = ipc.DecodeListenersKnown(m); err != nil {
			break
		}
		known(ids)
	}
	gone <- err // io.EOF means the worker's socket closed (it is exiting)
}
