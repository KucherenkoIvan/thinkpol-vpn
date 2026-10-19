//go:build linux && !android

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
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

	p, err := s.startWorker(w, child)
	if err != nil {
		return err
	}
	// The namespace fd was opened before Wait could reap the process, so the
	// pid can't have been recycled under it.
	defer func() {
		p.kill()
		_ = p.netns.Close()
	}()
	log = s.markStarted(w, p, log)

	wired, err := s.wire(w, p.netns)
	defer func() {
		if err := wired.unwire(); err != nil {
			log.Error("unwiring the worker's namespace", "err", err)
		}
	}()
	if err != nil {
		return fmt.Errorf("wire the namespace: %w", err)
	}

	sn := newSession(s, w, p, ends.Control, ends.Data, log)
	if stopped, err := sn.awaitReady(); stopped || err != nil {
		return err
	}
	return sn.serve()
}

// startWorker builds the worker's command for its space and starts it: the
// command is the supervisor's own with -space appended, the pair's child
// fds are its ControlFD and DataFD. The worker is fork+exec'd (not cloned)
// into a new user namespace with every other namespace created inside it.
func (s *Supervisor) startWorker(w *worker, child [2]*os.File) (*process, error) {
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
		return nil, fmt.Errorf("start: %w", err)
	}
	return p, nil
}

// markStarted records the process as the worker's current incarnation and
// logs it; from here on the log names the pid.
func (s *Supervisor) markStarted(w *worker, p *process, log *slog.Logger) *slog.Logger {
	w.mu.Lock()
	w.pid = p.pid
	w.starts++
	w.startedAt = s.opts.now()
	w.nextStart = time.Time{}
	w.mu.Unlock()
	log = log.With("pid", p.pid)
	log.Info("worker started")
	return log
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
