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
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// workerAmbientCaps are the capabilities a worker carries across exec, all
// confined to its own namespaces: SYS_ADMIN for the mounts and pivot_root in
// sandbox, SETPCAP to drop the capability bounding set afterwards, NET_ADMIN
// for its TUN, routes and nftables, NET_RAW for the data plane and
// NET_BIND_SERVICE for its DNS resolver on port 53. sandbox drops SYS_ADMIN
// and SETPCAP once it is done with them.
var workerAmbientCaps = []uintptr{
	unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP, unix.CAP_NET_ADMIN, unix.CAP_NET_RAW, unix.CAP_NET_BIND_SERVICE,
}

// supervise runs w's processes one after another until w is stopped,
// pausing between them by the backoff.
func (s *Supervisor) supervise(w *worker) {
	defer close(w.done)
	log := s.log.With("space", w.space.String(), "link", w.link)
	var delay time.Duration
	for {
		started := s.opts.now()
		err := s.run(w, log)
		w.mu.Lock()
		w.pid, w.ready = 0, false
		if err != nil {
			w.lastExit = err.Error()
		}
		w.mu.Unlock()
		if w.ctx.Err() != nil {
			log.Info("worker stopped", "err", err)
			return
		}
		delay = s.opts.Backoff.next(delay, s.opts.now().Sub(started))
		w.mu.Lock()
		w.nextStart = s.opts.now().Add(delay)
		w.mu.Unlock()
		log.Warn("worker exited, restarting", "err", err, "in", delay)
		select {
		case <-w.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// run is one worker process, from exec to cleanup. It returns why the
// process ended: nil only when it exited cleanly after Stop.
func (s *Supervisor) run(w *worker, log *slog.Logger) error {
	ends, child, err := ipc.NewPair()
	if err != nil {
		return err
	}
	defer func() { _ = ends.Control.Close(); _ = ends.Data.Close() }()

	cmd := exec.Command(s.opts.Command[0], append(slices.Clone(s.opts.Command[1:]), "-space", w.space.String())...)
	if cmd.Path == selfExe {
		cmd.Args[0] = "thinkpol"
	}
	cmd.Env = s.opts.Env
	cmd.Dir = "/"
	var out io.Writer = w.output
	if s.opts.Output != nil {
		if extra := s.opts.Output(w.space); extra != nil {
			out = io.MultiWriter(w.output, extra)
		}
	}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.ExtraFiles = child[:] // ControlFD, DataFD
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// A new user namespace first, with every other namespace created
		// inside it, so the worker's capabilities (NET_ADMIN and the rest)
		// apply only to its own namespaces: it maps to an unprivileged host
		// uid and has no power over the root namespace's links.
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | unix.CLONE_NEWCGROUP,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(w.uid), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(w.uid), Size: 1}},
		GidMappingsEnableSetgroups: true,
		// The child inherits host uid 0, which the map above doesn't cover, so
		// without this it would be the overflow "nobody" uid inside its
		// namespace. Becoming uid 0 there (host w.uid) makes it the namespace
		// root that owns its mounts and interfaces; an empty Groups clears the
		// supplementary groups it would otherwise inherit.
		Credential: &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}},
		// Ambient capabilities survive the exec; a process that is uid 0 in a
		// new user namespace (mapped to an unprivileged host uid) would
		// otherwise lose all capabilities, because the kernel's "root keeps
		// caps across exec" shortcut checks the global root uid. These apply
		// only inside the worker's own namespaces.
		AmbientCaps: workerAmbientCaps,
		Setsid:      true,
		Pdeathsig:   syscall.SIGKILL,
	}
	if w.cg != nil {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = w.cg.fd()
	}
	p, err := start(cmd)
	for _, f := range child {
		_ = f.Close()
	}
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	// The namespace fd was opened before Wait could reap the process, so the
	// pid can't have been recycled under it.
	defer func() {
		p.kill()
		_ = p.netns.Close()
	}()
	w.mu.Lock()
	w.pid = p.pid
	w.starts++
	w.startedAt = s.opts.now()
	w.nextStart = time.Time{}
	w.mu.Unlock()
	log = log.With("pid", p.pid)
	log.Info("worker started")

	wired, err := s.wire(w, p.netns)
	defer func() {
		if err := wired.unwire(); err != nil {
			log.Error("unwiring the worker's namespace", "err", err)
		}
	}()
	if err != nil {
		return fmt.Errorf("wire the namespace: %w", err)
	}

	init, err := ipc.InitMessage(ipc.Init{
		Space:     w.space.String(),
		Interface: SpaceInterface,
		Addrs:     w.transit.space[:],
		Gateways:  []netip.Addr{w.transit.root[0].Addr(), w.transit.root[1].Addr()},
		UID:       w.uid,
		GID:       w.uid,
		PidsMax:   s.opts.PidsMax,
	})
	if err != nil {
		return err
	}
	if err := ends.Control.Send(init); err != nil {
		return err
	}

	ready, gone := make(chan error, 1), make(chan error, 1)
	go readControl(ends.Control, ready, gone)
	timer := time.NewTimer(s.opts.ReadyTimeout)
	defer timer.Stop()
	select {
	case err := <-ready:
		if err != nil {
			return fmt.Errorf("before ready: %w", err)
		}
	case <-p.gone:
		return fmt.Errorf("before ready: %w", p.exit())
	case <-timer.C:
		return fmt.Errorf("not ready after %v", s.opts.ReadyTimeout)
	case <-w.ctx.Done():
		return nil
	}
	w.mu.Lock()
	w.ready = true
	w.readyAt = s.opts.now()
	w.mu.Unlock()
	log.Info("worker ready")

	// A control send that can't finish within StopTimeout means the worker
	// stopped reading its socket: it is killed (and restarted), so it can't
	// hold up SetSpaces, SetListeners or Close.
	stuck := func(what string, err error) error {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			// The worker is gone or going: its exit is the reason.
			s.awaitExit(p)
			return p.exit()
		}
		_ = ends.Control.Close()
		p.kill()
		return fmt.Errorf("sending %s: %w", what, err)
	}
	// The listeners and the current config once, then whenever they
	// change; datagrams and connections from now on.
	if err := s.sendListeners(ends.Control); err != nil {
		return stuck("listeners", err)
	}
	// Each seed once per process, ahead of the config that names it.
	sent := map[[32]byte]bool{}
	if err := s.sendSeeds(ends.Control, w, sent); err != nil {
		return stuck("blob seeds", err)
	}
	if err := s.sendConfig(ends.Control, w); err != nil {
		return stuck("config", err)
	}
	countersTick := time.NewTicker(s.opts.CountersInterval)
	defer countersTick.Stop()
	detach := s.shared.attach(transport.SpaceID(w.space), &workerSockets{data: ends.Data, control: ends.Control})
	defer detach()
	dataGone := make(chan error, 1)
	go s.readReplies(ends.Data, transport.SpaceID(w.space), dataGone)
	for {
		select {
		case <-p.gone:
			return p.exit()
		case err := <-dataGone:
			if errors.Is(err, io.EOF) {
				continue // the control socket or the exit tells why
			}
			_ = ends.Control.Close()
			s.awaitExit(p)
			return fmt.Errorf("data socket: %w", err)
		case <-w.listenersChanged:
			if err := s.sendListeners(ends.Control); err != nil {
				return stuck("listeners", err)
			}
		case <-countersTick.C:
			// For the worker's telemetry; skipped when the socket is full.
			if m, err := ipc.CountersMessage(s.shared.counters(transport.SpaceID(w.space))); err == nil {
				_ = ends.Control.TrySend(m)
			}
		case err := <-gone:
			if errors.Is(err, io.EOF) {
				// The worker's control socket closed: it has exited or is
				// exiting, so its own exit is the reason.
				s.awaitExit(p)
				return p.exit()
			}
			// A protocol break while the worker is still running: that is the
			// reason, whatever its incidental exit code.
			_ = ends.Control.Close()
			s.awaitExit(p)
			return fmt.Errorf("socket: %w", err)
		case <-w.notify:
			if err := s.sendSeeds(ends.Control, w, sent); err != nil {
				return stuck("blob seeds", err)
			}
			if err := s.sendConfig(ends.Control, w); err != nil {
				return stuck("config", err)
			}
		case <-w.egressChanged:
			// The root namespace's tables already follow the new egress,
			// whatever this one does; a failure is retried with the next
			// change, or in a fresh namespace.
			if err := applySpaceTable(p.netns, w.transit, s.currentSpaceEgress(w)); err != nil {
				log.Error("the space's egress table", "err", err)
			}
		case <-w.ctx.Done():
			if err := ends.Control.SendTimeout(ipc.Message{Kind: ipc.KindStop}, s.opts.StopTimeout); err != nil {
				log.Warn("sending stop", "err", err)
				p.kill()
				return fmt.Errorf("killed: %w", err)
			}
			if !s.awaitExit(p) {
				return fmt.Errorf("killed: still running %v after stop", s.opts.StopTimeout)
			}
			if p.err != nil {
				return p.err
			}
			return nil
		}
	}
}

// sendListeners tells a worker which shared listeners it is forwarded from.
func (s *Supervisor) sendListeners(conn *ipc.Conn) error {
	m, err := ipc.ListenersMessage(s.shared.ipcListeners())
	if err != nil {
		return err
	}
	return conn.SendTimeout(m, s.opts.StopTimeout)
}

// readReplies sends out the datagrams a worker writes to its data socket,
// until the socket closes or the worker breaks the protocol (reported on
// gone; io.EOF when it closed).
func (s *Supervisor) readReplies(data *ipc.Conn, space transport.SpaceID, gone chan<- error) {
	for {
		m, err := data.Receive()
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
		s.shared.reply(space, h, d)
	}
}

// sendConfig sends the worker's current configuration, as a sealed memfd when
// it is too large for one packet.
func (s *Supervisor) sendConfig(conn *ipc.Conn, w *worker) error {
	config := w.currentConfig()
	if len(config) == 0 {
		return nil
	}
	if 1+len(config) <= ipc.MaxMessageSize {
		return conn.SendTimeout(ipc.ConfigMessage(config), s.opts.StopTimeout)
	}
	f, err := sealedMemfd("thinkpol-config", config)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return conn.SendTimeout(ipc.Message{Kind: ipc.KindConfig, Files: []*os.File{f}}, s.opts.StopTimeout)
}

// sendSeeds sends the worker each of its space's current seeds it hasn't
// had (sent), one sealed memfd per seed; nothing of them is kept here.
func (s *Supervisor) sendSeeds(conn *ipc.Conn, w *worker, sent map[[32]byte]bool) error {
	seeds := w.currentSeeds()
	if seeds == nil {
		return nil
	}
	for _, b := range seeds() {
		sum := sha256.Sum256(b)
		if sent[sum] || len(b) == 0 || len(b) > ipc.MaxBlobSize {
			continue
		}
		f, err := sealedMemfd("thinkpol-blob", b)
		if err != nil {
			return err
		}
		err = conn.SendTimeout(ipc.Message{Kind: ipc.KindBlob, Files: []*os.File{f}}, s.opts.StopTimeout)
		_ = f.Close()
		if err != nil {
			return err
		}
		sent[sum] = true
	}
	return nil
}

// awaitExit gives the process StopTimeout to exit, then kills it; false if
// it had to.
func (s *Supervisor) awaitExit(p *process) bool {
	timer := time.NewTimer(s.opts.StopTimeout)
	defer timer.Stop()
	select {
	case <-p.gone:
		return true
	case <-timer.C:
		p.kill()
		return false
	}
}

// readControl reports the worker's Ready on ready, then anything after it on
// gone (for now every further message is a protocol error, EOF included).
func readControl(conn *ipc.Conn, ready, gone chan<- error) {
	m, err := conn.Receive()
	if err == nil && m.Kind != ipc.KindReady {
		m.CloseFiles()
		err = fmt.Errorf("unexpected %v message", m.Kind)
	}
	ready <- err
	if err != nil {
		return
	}
	m, err = conn.Receive()
	if err == nil {
		m.CloseFiles()
		err = fmt.Errorf("unexpected %v message", m.Kind)
	}
	gone <- err // io.EOF means the worker's socket closed (it is exiting)
}

// process is a started worker process with its network namespace held open.
type process struct {
	cmd   *exec.Cmd
	pid   int
	netns *os.File
	gone  chan struct{} // closed once reaped
	err   error         // Wait's result, set before gone closes
}

// start starts cmd from a goroutine locked to its OS thread for the
// process's whole life (the parent-death signal fires when the thread that
// forked the child exits, and Go ends a thread whose goroutine exits while
// locked), and opens the child's network namespace before Wait can reap it,
// so the pid can't be recycled under the open.
func start(cmd *exec.Cmd) (*process, error) {
	p := &process{cmd: cmd, gone: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			runtime.UnlockOSThread()
			started <- err
			close(p.gone)
			return
		}
		p.pid = cmd.Process.Pid
		p.netns, p.err = os.Open(fmt.Sprintf("/proc/%d/ns/net", p.pid))
		started <- p.err
		if p.err != nil {
			_ = cmd.Process.Kill()
		}
		p.err = cmd.Wait()
		runtime.UnlockOSThread()
		close(p.gone)
	}()
	if err := <-started; err != nil {
		<-p.gone // let Wait reap it
		return nil, err
	}
	return p, nil
}

// kill kills the process unless it is gone already, and reaps it.
func (p *process) kill() {
	select {
	case <-p.gone:
	default:
		_ = p.cmd.Process.Kill()
		<-p.gone
	}
}

// exit is why a process that is gone ended, never nil: it wasn't asked to.
func (p *process) exit() error {
	if p.err == nil {
		return errors.New("exited")
	}
	return p.err
}
