//go:build linux && !android

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const selfExe = "/proc/self/exe"

// Supervisor runs one worker per space, each in its own network, mount and
// PID namespaces, wired to the root namespace by a veth pair. Its methods
// are safe for concurrent use.
type Supervisor struct {
	opts Options
	log  *slog.Logger
	// root is held for the supervisor's life: one supervisor per node
	// (netcfg.ErrBusy for a second), and where root-namespace routes go
	// when one is needed.
	root netcfg.Configurator

	setMu sync.Mutex // one SetSpaces at a time

	mu      sync.Mutex
	workers map[netmap.SpaceID]*worker
	slots   map[int]bool
	closed  bool
}

// New starts a supervisor with no spaces: it takes the node's supervisor
// role, removes what a dead predecessor left (veths, its nftables table)
// and installs the table that keeps spaces apart in the root namespace.
func New(opts Options) (*Supervisor, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	if len(opts.Command) == 0 {
		// The running binary itself, even once an update replaced the file:
		// a worker is always the supervisor's own build, which the socket
		// protocol relies on.
		opts.Command = []string{selfExe, "worker"}
	}
	root, err := netcfg.New(netcfg.OwnerSupervisor)
	if err != nil {
		return nil, fmt.Errorf("supervisor: %w", err)
	}
	s := &Supervisor{opts: opts, log: opts.Log, root: root, workers: map[netmap.SpaceID]*worker{}, slots: map[int]bool{}}
	fail := func(err error) (*Supervisor, error) {
		_ = removeIsolation()
		_ = root.Close()
		return nil, fmt.Errorf("supervisor: %w", err)
	}
	// The predecessor's routes, if any; the supervisor adds none yet.
	if err := root.Apply(context.Background(), netcfg.Config{}); err != nil {
		return fail(err)
	}
	if err := removeStaleLinks(s.log); err != nil {
		return fail(err)
	}
	if err := installIsolation(); err != nil {
		return fail(err)
	}
	return s, nil
}

// removeStaleLinks deletes veths named like a space's: only a dead
// supervisor can have left them, since this one holds the node's role.
func removeStaleLinks(log *slog.Logger) error {
	links, err := linkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		if _, ok := l.(*netlink.Veth); !ok || !strings.HasPrefix(l.Attrs().Name, LinkPrefix) {
			continue
		}
		log.Warn("removing a dead supervisor's veth", "link", l.Attrs().Name)
		if err := netlink.LinkDel(l); err != nil && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("remove stale %s: %w", l.Attrs().Name, err)
		}
	}
	return nil
}

// linkList lists the root namespace's links, again when a change raced the
// dump (netlink.ErrDumpInterrupted: the list may be inconsistent), as when
// a dead supervisor's veths are still going away with their namespaces.
func linkList() ([]netlink.Link, error) {
	for range 10 {
		links, err := netlink.LinkList()
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return links, err
		}
	}
	return nil, fmt.Errorf("links kept changing: %w", netlink.ErrDumpInterrupted)
}

// SetSpaces makes the supervisor serve exactly spaces: workers of spaces no
// longer listed are stopped and their namespaces removed (SetSpaces waits
// for that), workers of new ones started. Workers of spaces that stay are
// left alone.
func (s *Supervisor) SetSpaces(spaces []netmap.SpaceID) error {
	want := make(map[netmap.SpaceID]bool, len(spaces))
	for _, id := range spaces {
		if id.IsZero() {
			return errors.New("supervisor: zero space id")
		}
		if want[id] {
			return fmt.Errorf("supervisor: space %s listed twice", id)
		}
		want[id] = true
	}
	s.setMu.Lock()
	defer s.setMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("supervisor: closed")
	}
	if len(want) > s.opts.slots() {
		s.mu.Unlock()
		return fmt.Errorf("supervisor: %d spaces, room for %d", len(want), s.opts.slots())
	}
	var stopping []*worker
	for id, w := range s.workers {
		if !want[id] {
			stopping = append(stopping, w)
			delete(s.workers, id)
		}
	}
	s.mu.Unlock()

	s.stopAll(stopping)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("supervisor: closed")
	}
	for _, id := range spaces {
		if _, ok := s.workers[id]; ok {
			continue
		}
		slot := 0
		for s.slots[slot] {
			slot++
		}
		s.slots[slot] = true
		w := s.newWorker(id, slot)
		s.workers[id] = w
		go s.supervise(w)
	}
	return nil
}

func (s *Supervisor) stopAll(ws []*worker) {
	for _, w := range ws {
		w.cancel()
	}
	for _, w := range ws {
		<-w.done
		s.mu.Lock()
		delete(s.slots, w.slot)
		s.mu.Unlock()
	}
}

// Workers describes every space's worker, ordered by slot.
func (s *Supervisor) Workers() []WorkerInfo {
	s.mu.Lock()
	ws := make([]*worker, 0, len(s.workers))
	for _, w := range s.workers {
		ws = append(ws, w)
	}
	s.mu.Unlock()
	slices.SortFunc(ws, func(a, b *worker) int { return a.slot - b.slot })
	out := make([]WorkerInfo, len(ws))
	for i, w := range ws {
		out[i] = w.info()
	}
	return out
}

// Output is what a space's worker processes wrote, newest last, from an
// in-memory ring; nil for a space not served.
func (s *Supervisor) Output(space netmap.SpaceID) []string {
	s.mu.Lock()
	w := s.workers[space]
	s.mu.Unlock()
	if w == nil {
		return nil
	}
	return w.output.Lines()
}

// Close stops every worker, removes every namespace, veth and the nftables
// table, and gives up the node's supervisor role.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ws := make([]*worker, 0, len(s.workers))
	for _, w := range s.workers {
		ws = append(ws, w)
	}
	clear(s.workers)
	s.mu.Unlock()

	s.stopAll(ws)
	var errs []error
	if err := removeIsolation(); err != nil {
		errs = append(errs, err)
	}
	if err := s.root.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("supervisor: close: %w", err)
	}
	return nil
}

// worker is one space's worker across its restarts.
type worker struct {
	space   netmap.SpaceID
	slot    int
	link    string
	transit transit
	uid     uint32
	output  *logring.Ring
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{} // closed once stopped and cleaned up

	mu       sync.Mutex
	pid      int
	ready    bool
	starts   int
	lastExit string
}

func (s *Supervisor) newWorker(id netmap.SpaceID, slot int) *worker {
	ctx, cancel := context.WithCancel(context.Background())
	return &worker{
		space:   id,
		slot:    slot,
		link:    linkName(slot),
		transit: s.opts.transit(slot),
		uid:     s.opts.UIDBase + uint32(slot),
		output:  logring.New(s.opts.OutputBytes),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
}

func (w *worker) info() WorkerInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WorkerInfo{
		Space:      w.space,
		Link:       w.link,
		RootAddrs:  slices.Clone(w.transit.root[:]),
		SpaceAddrs: slices.Clone(w.transit.space[:]),
		UID:        w.uid,
		PID:        w.pid,
		Ready:      w.ready,
		Starts:     w.starts,
		LastExit:   w.lastExit,
	}
}

// supervise runs w's processes one after another until w is stopped,
// pausing between them by the backoff.
func (s *Supervisor) supervise(w *worker) {
	defer close(w.done)
	log := s.log.With("space", w.space.String(), "link", w.link)
	var delay time.Duration
	for {
		started := time.Now()
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
		delay = s.opts.Backoff.next(delay, time.Since(started))
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
	conn, child, err := ipc.Pair()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	cmd := exec.Command(s.opts.Command[0], append(slices.Clone(s.opts.Command[1:]), "-space", w.space.String())...)
	if cmd.Path == selfExe {
		cmd.Args[0] = "thinkpol"
	}
	cmd.Env = s.opts.Env
	cmd.Stdout, cmd.Stderr = w.output, w.output
	cmd.ExtraFiles = []*os.File{child} // ipc.WorkerFD
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID,
		// The runtime remounts / private for an unshared mount namespace,
		// so the worker's mounts stay its own.
		Unshareflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		Pdeathsig:    syscall.SIGKILL,
	}
	p, err := start(cmd)
	_ = child.Close()
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	w.mu.Lock()
	w.pid = p.pid
	w.starts++
	w.mu.Unlock()
	log = log.With("pid", p.pid)
	log.Info("worker started")

	// The process is gone before its namespace is unwired; holding the
	// namespace keeps it, and the veth in it, until then.
	var ns *os.File
	var wired *wiring
	defer func() {
		p.kill()
		if err := wired.unwire(); err != nil {
			log.Error("unwiring the worker's namespace", "err", err)
		}
		if ns != nil {
			_ = ns.Close()
		}
	}()
	if ns, err = os.Open(fmt.Sprintf("/proc/%d/ns/net", p.pid)); err != nil {
		return fmt.Errorf("worker's namespace: %w", err)
	}
	if wired, err = s.wire(w, ns); err != nil {
		return fmt.Errorf("wire the namespace: %w", err)
	}

	init, err := ipc.InitMessage(ipc.Init{
		Space:     w.space.String(),
		Interface: SpaceInterface,
		Addrs:     w.transit.space[:],
		Gateways:  []netip.Addr{w.transit.root[0].Addr(), w.transit.root[1].Addr()},
		UID:       w.uid,
		GID:       w.uid,
	})
	if err != nil {
		return err
	}
	if err := conn.Send(init); err != nil {
		return err
	}

	ready, gone := make(chan error, 1), make(chan error, 1)
	go read(conn, ready, gone)
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
	w.mu.Unlock()
	log.Info("worker ready")

	select {
	case <-p.gone:
		return p.exit()
	case err := <-gone:
		// The worker closed its socket or broke the protocol: it gets
		// StopTimeout to exit on its own, and how it exited says more.
		if s.awaitExit(p) {
			return p.exit()
		}
		return fmt.Errorf("socket: %w; killed", err)
	case <-w.ctx.Done():
		if err := conn.Send(ipc.Message{Kind: ipc.KindStop}); err != nil {
			log.Warn("sending stop", "err", err)
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

// read reports the worker's Ready on ready, then anything after it on gone
// (for now every further message is a protocol error, EOF included).
func read(conn *ipc.Conn, ready, gone chan<- error) {
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
	if errors.Is(err, io.EOF) {
		err = errors.New("closed by the worker")
	}
	gone <- err
}

// process is a started worker process.
type process struct {
	cmd  *exec.Cmd
	pid  int
	gone chan struct{} // closed once reaped
	err  error         // Wait's result, set before gone closes
}

// start starts cmd from a goroutine locked to its OS thread for the
// process's whole life: the parent-death signal fires when the thread that
// forked the child exits, and Go ends a thread whose goroutine exits while
// locked.
func start(cmd *exec.Cmd) (*process, error) {
	p := &process{cmd: cmd, gone: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			runtime.UnlockOSThread()
			started <- err
			return
		}
		p.pid = cmd.Process.Pid
		started <- nil
		p.err = cmd.Wait()
		runtime.UnlockOSThread()
		close(p.gone)
	}()
	if err := <-started; err != nil {
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
