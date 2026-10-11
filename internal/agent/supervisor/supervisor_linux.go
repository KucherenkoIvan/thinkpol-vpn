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
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const selfExe = "/proc/self/exe"

// workerAmbientCaps are the capabilities a worker carries across exec, all
// confined to its own namespaces: SYS_ADMIN for the mounts and pivot_root in
// sandbox, SETPCAP to drop the capability bounding set afterwards, NET_ADMIN
// for its TUN, routes and nftables, NET_RAW for the data plane and
// NET_BIND_SERVICE for its DNS resolver on port 53. sandbox drops SYS_ADMIN
// and SETPCAP once it is done with them.
var workerAmbientCaps = []uintptr{
	unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP, unix.CAP_NET_ADMIN, unix.CAP_NET_RAW, unix.CAP_NET_BIND_SERVICE,
}

// Supervisor runs one worker per space, each in its own user, network, mount,
// PID, IPC, UTS and cgroup namespaces, wired to the root namespace by a veth
// pair. Its methods are safe for concurrent use.
type Supervisor struct {
	opts    Options
	log     *slog.Logger
	cgroups *cgroupParent // nil when cgroup v2 isn't usable (rlimits only)
	// root is held for the supervisor's life: one supervisor per node
	// (netcfg.ErrBusy for a second), and where root-namespace routes go
	// when one is needed.
	root netcfg.Configurator
	// shared is the public listeners, routing to the workers.
	shared *shared

	setMu sync.Mutex // one SetSpaces (or Close teardown) at a time

	mu      sync.Mutex
	workers map[netmap.SpaceID]*worker
	slots   map[int]bool
	closed  bool
}

// New starts a supervisor with no spaces: it takes the node's supervisor
// role, removes what a dead predecessor left (veths, its nftables tables)
// and installs the tables that keep spaces apart in the root namespace.
func New(opts Options) (*Supervisor, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	if len(opts.Command) == 0 {
		// The running binary itself, even once an update replaced the file:
		// a worker is always the supervisor's own build, which the IPC
		// version check confirms.
		opts.Command = []string{selfExe, "worker"}
	}
	root, err := netcfg.New(netcfg.OwnerSupervisor)
	if err != nil {
		return nil, fmt.Errorf("supervisor: %w", err)
	}
	s := &Supervisor{
		opts: opts, log: opts.Log, root: root,
		shared:  newShared(opts.Transports, opts.FairShare, opts.Log, opts.now),
		workers: map[netmap.SpaceID]*worker{}, slots: map[int]bool{},
	}
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
	if err := s.installIsolation(); err != nil {
		return fail(err)
	}
	// Resource limits are best-effort: where cgroup v2 can't be delegated
	// the worker falls back to its own rlimits.
	if cg, err := newCgroupParent(); err != nil {
		s.log.Warn("cgroup v2 unavailable, workers limited by rlimits only", "err", err)
	} else {
		s.cgroups = cg
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
		if !strings.HasPrefix(l.Attrs().Name, LinkPrefix) {
			continue
		}
		log.Warn("removing a dead supervisor's leftover link", "link", l.Attrs().Name)
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
// for that), workers of new ones started. A space already served keeps its
// worker; its configuration is updated and pushed to the running worker.
func (s *Supervisor) SetSpaces(spaces []Space) error {
	want := make(map[netmap.SpaceID]Space, len(spaces))
	for _, sp := range spaces {
		if sp.ID.IsZero() {
			return errors.New("supervisor: zero space id")
		}
		if _, dup := want[sp.ID]; dup {
			return fmt.Errorf("supervisor: space %s listed twice", sp.ID)
		}
		want[sp.ID] = sp
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
	// The credential tables first: a space leaving is unreachable before
	// its worker stops, and a new one routable once its worker is ready.
	inbound := make(map[transport.SpaceID]map[string][]transport.PeerLink, len(want))
	for id, sp := range want {
		inbound[transport.SpaceID(id)] = sp.Inbound
	}
	s.shared.setSpaces(inbound)
	var stopping []*worker
	for id, w := range s.workers {
		if _, ok := want[id]; !ok {
			stopping = append(stopping, w)
			delete(s.workers, id)
		}
	}
	s.mu.Unlock()

	s.stopAll(stopping)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("supervisor: closed")
	}
	var started []*worker
	for _, sp := range spaces {
		if w, ok := s.workers[sp.ID]; ok {
			w.inbound = sp.Inbound
			w.setConfig(sp.Config) // an existing worker: push the new config
			continue
		}
		slot := 0
		for s.slots[slot] {
			slot++
		}
		s.slots[slot] = true
		w := s.newWorker(sp, slot)
		s.workers[sp.ID] = w
		started = append(started, w)
	}
	active := make([]int, 0, len(s.workers))
	for _, w := range s.workers {
		active = append(active, w.slot)
	}
	s.mu.Unlock()

	// Rebuild the isolation tables for the current slots before any new
	// worker's veth carries a packet. A slot is stable across a worker's
	// restarts, so this is a no-op unless the set changed. On failure the
	// just-started workers are rolled back: none has a goroutine yet, so a
	// later Close must not wait on them.
	if err := s.applyIsolation(active); err != nil {
		s.rollback(started)
		return err
	}
	for _, w := range started {
		go s.supervise(w)
	}
	return nil
}

// rollback drops workers that were registered but never started (their done
// channel would never close): remove them, free their slots and cgroups.
func (s *Supervisor) rollback(ws []*worker) {
	s.mu.Lock()
	for _, w := range ws {
		delete(s.workers, w.space)
		delete(s.slots, w.slot)
	}
	// The shared listeners stop routing to the spaces rolled back.
	inbound := make(map[transport.SpaceID]map[string][]transport.PeerLink, len(s.workers))
	for id, w := range s.workers {
		inbound[transport.SpaceID(id)] = w.inbound
	}
	s.mu.Unlock()
	s.shared.setSpaces(inbound)
	for _, w := range ws {
		close(w.done) // it was never supervised; keep Workers()/Close consistent
		if w.cg != nil {
			if err := w.cg.remove(); err != nil {
				s.log.Warn("removing a rolled-back worker's cgroup", "space", w.space.String(), "err", err)
			}
		}
	}
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
		if w.cg != nil {
			if err := w.cg.remove(); err != nil {
				s.log.Warn("removing a worker's cgroup", "space", w.space.String(), "err", err)
			}
		}
	}
}

// SetListeners makes the node listen on exactly ls, for every space it
// serves (see Listener). Listeners that stay keep their sockets. A listener
// that can't be opened is reported and the others are served. Every worker
// is told the new set.
func (s *Supervisor) SetListeners(ls []Listener) error {
	changed, err := s.shared.setListeners(context.Background(), ls)
	if changed {
		s.mu.Lock()
		for _, w := range s.workers {
			w.signal(w.listenersChanged)
		}
		s.mu.Unlock()
	}
	return err
}

// Listeners describes the public listeners, ordered by id.
func (s *Supervisor) Listeners() []ListenerInfo { return s.shared.infos() }

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
		out[i].Shared = s.shared.counters(transport.SpaceID(w.space))
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

// Close stops every worker, removes every namespace, veth and nftables
// table, and gives up the node's supervisor role. It waits for any in-flight
// SetSpaces first, so nothing is half-started when the tables and lock go.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.shared.close()

	s.setMu.Lock() // wait for an in-flight SetSpaces to finish
	defer s.setMu.Unlock()

	s.mu.Lock()
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
	if s.cgroups != nil {
		if err := s.cgroups.remove(); err != nil {
			errs = append(errs, err)
		}
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
	egress  Egress
	inbound map[string][]transport.PeerLink // under Supervisor.mu
	output  *logring.Ring
	cg      *cgroup // nil when cgroups are unavailable
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{} // closed once stopped and cleaned up
	notify  chan struct{} // config changed; coalesced
	// listenersChanged: the shared listeners changed; coalesced
	listenersChanged chan struct{}

	mu        sync.Mutex
	config    []byte
	pid       int
	ready     bool
	starts    int
	startedAt time.Time
	readyAt   time.Time
	nextStart time.Time
	lastExit  string
}

func (s *Supervisor) newWorker(sp Space, slot int) *worker {
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{
		space:   sp.ID,
		slot:    slot,
		link:    linkName(slot),
		transit: s.opts.transit(slot),
		uid:     s.opts.UIDBase + uint32(slot),
		egress:  sp.Egress,
		inbound: sp.Inbound,
		config:  sp.Config,
		output:  logring.New(s.opts.OutputBytes),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
		notify:  make(chan struct{}, 1),

		listenersChanged: make(chan struct{}, 1),
	}
	if s.cgroups != nil {
		cg, err := s.cgroups.child(w.link, s.opts.MemoryMax, s.opts.PidsMax)
		if err != nil {
			s.log.Warn("creating a worker's cgroup", "space", w.space.String(), "err", err)
		} else {
			w.cg = cg
		}
	}
	return w
}

// setConfig stores a new config and signals the running worker to send it.
func (w *worker) setConfig(config []byte) {
	w.mu.Lock()
	same := string(w.config) == string(config)
	w.config = config
	w.mu.Unlock()
	if !same {
		w.signal(w.notify)
	}
}

// signal wakes the worker's run loop through ch, coalescing.
func (w *worker) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (w *worker) currentConfig() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.config
}

func (w *worker) info() WorkerInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WorkerInfo{
		Space:         w.space,
		Link:          w.link,
		RootAddrs:     slices.Clone(w.transit.root[:]),
		SpaceAddrs:    slices.Clone(w.transit.space[:]),
		UID:           w.uid,
		PID:           w.pid,
		Ready:         w.ready,
		Starts:        w.starts,
		StartedAt:     w.startedAt,
		ReadyAt:       w.readyAt,
		NextStart:     w.nextStart,
		LastExit:      w.lastExit,
		OutputDropped: w.output.Dropped(),
	}
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
	cmd.Stdout, cmd.Stderr = w.output, w.output
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
			if err := s.sendConfig(ends.Control, w); err != nil {
				return stuck("config", err)
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
