//go:build linux && !android

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/egress"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const selfExe = "/proc/self/exe"

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
	// forwarding is what the supervisor turned on in the root namespace's
	// sysctls for its spaces' egress and dials, restored on Close.
	forwarding rootForwarding

	setMu sync.Mutex // one SetSpaces (or Close teardown) at a time

	mu      sync.Mutex
	workers map[netmap.SpaceID]*worker
	slots   map[int]bool
	closed  bool
	// uplink is the node's uplink as last found (uplinkErr when there is
	// none); maxFlows caps each space's flows through the root (0: none).
	uplink    egress.Uplink
	uplinkErr error
	maxFlows  int
	// stopWatch ends the route watcher; watchDone is closed when it has.
	stopWatch chan struct{}
	watchDone chan struct{}
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
	if opts.NewRoot == nil {
		return nil, errors.New("supervisor: no NewRoot")
	}
	root, err := opts.NewRoot()
	if err != nil {
		return nil, fmt.Errorf("supervisor: %w", err)
	}
	s := &Supervisor{
		opts: opts, log: opts.Log, root: root,
		shared:  newShared(opts.Transports, opts.FairShare, opts.Log, opts.now),
		workers: map[netmap.SpaceID]*worker{}, slots: map[int]bool{},
		forwarding: rootForwarding{sys: opts.sysctls},
		maxFlows:   maxFlows(opts.MaxFlowsPerSpace, opts.sysctls),
		stopWatch:  make(chan struct{}), watchDone: make(chan struct{}),
	}
	// A predecessor's forwarding, if it died without restoring it: still
	// the supervisor's to confine and put back, even if this start fails.
	if err := s.forwarding.load(opts.RuntimeDir); err != nil {
		s.log.Warn("reading what a predecessor changed in the forwarding sysctls", "err", err)
	}
	fail := func(err error) (*Supervisor, error) {
		if err := s.putBackForwarding(); err != nil {
			s.log.Error("putting back the forwarding sysctls", "err", err)
		}
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
	s.refreshUplink()
	if err := s.installIsolation(); err != nil {
		return fail(err)
	}
	if err := s.forwarding.ensure([2]bool{}); err != nil {
		s.log.Warn("restoring the forwarding sysctls", "err", err)
	}
	go s.watchRoutes()
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
	want, err := validateSpaces(spaces)
	if err != nil {
		return err
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
	// What each running space's table forwards now, before the uplink
	// and the grants change: a space whose differs after is told.
	before := s.spaceEgresses()
	was := s.saveEgress()
	s.refreshUplinkLocked()
	var started []*worker
	for _, sp := range spaces {
		if w, ok := s.workers[sp.ID]; ok {
			w.inbound = sp.Inbound
			w.setEgress(sp.Egress, sp.Dials)
			w.setConfig(sp.Config, sp.Seeds) // an existing worker: push the new config
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
	s.mu.Unlock()

	// Rebuild the isolation tables for the current slots, their egress and
	// dials, before any new worker's veth carries a packet. On failure the
	// just-started workers are rolled back: none has a goroutine yet, so a
	// later Close must not wait on them. What the tables are built from is
	// put back to what they still enforce, so the next SetSpaces sees the
	// difference and applies it.
	if err := s.applyTables(before); err != nil {
		s.rollback(started)
		s.restoreEgress(was)
		return err
	}
	for _, w := range started {
		go s.supervise(w)
	}
	return nil
}

// validateSpaces checks the spaces' ids, dials and uniqueness, and returns
// them by id.
func validateSpaces(spaces []Space) (map[netmap.SpaceID]Space, error) {
	want := make(map[netmap.SpaceID]Space, len(spaces))
	for _, sp := range spaces {
		if sp.ID.IsZero() {
			return nil, errors.New("supervisor: zero space id")
		}
		for _, d := range sp.Dials {
			if !d.Address.IsValid() || d.Address.Port() == 0 || d.Address.Addr().Zone() != "" || (d.Network != "udp" && d.Network != "tcp") {
				return nil, fmt.Errorf("supervisor: space %s: dial %v over %q", sp.ID, d.Address, d.Network)
			}
		}
		if _, dup := want[sp.ID]; dup {
			return nil, fmt.Errorf("supervisor: space %s listed twice", sp.ID)
		}
		want[sp.ID] = sp
	}
	return want, nil
}

// applyTables rebuilds the root namespace's tables and forwarding for what
// the supervisor serves now; then each space whose egress differs from
// before has its namespace's table rewritten (by its run loop) and its old
// flows flushed. The caller holds setMu.
func (s *Supervisor) applyTables(before map[*worker]spaceEgress) error {
	s.mu.Lock()
	st := s.tableState()
	want := forwardingWanted(st)
	st.owned = s.forwarding.willOwn(want)
	after := s.spaceEgresses()
	s.mu.Unlock()
	if err := s.applyIsolation(st); err != nil {
		return err
	}
	if err := s.forwarding.ensure(want); err != nil {
		s.log.Warn("forwarding sysctls: egress may be off", "err", err)
	}
	for w, e := range after {
		if old, ok := before[w]; ok && old != e {
			w.signal(w.egressChanged)
			if err := flushFlows(w.transit); err != nil {
				s.log.Warn("flushing a space's flows", "space", w.space.String(), "err", err)
			}
		}
	}
	return nil
}

// forwardingWanted are the families some space sends on: by egress, or by
// a dial (which leaves by the uplink too).
func forwardingWanted(st tableState) [2]bool {
	var want [2]bool
	if st.uplink == "" {
		return want
	}
	for _, r := range st.rules {
		want[0], want[1] = want[0] || r.egress[0], want[1] || r.egress[1]
		for _, d := range r.dials {
			if d.Address.Addr().Unmap().Is4() {
				want[0] = true
			} else {
				want[1] = true
			}
		}
	}
	return want
}

// spaceEgresses is what each worker's namespace table should forward; the
// caller holds s.mu.
func (s *Supervisor) spaceEgresses() map[*worker]spaceEgress {
	out := make(map[*worker]spaceEgress, len(s.workers))
	for _, w := range s.workers {
		out[w] = s.spaceEgress(w)
	}
	return out
}

// spaceEgress is what w's namespace table should forward; the caller holds
// s.mu.
func (s *Supervisor) spaceEgress(w *worker) spaceEgress {
	grant, _ := w.egressRules()
	return spaceEgress{on: s.uplink.Name != "" && (grant.IPv4 || grant.IPv6), family: s.effective(grant)}
}

// currentSpaceEgress is spaceEgress, taking s.mu.
func (s *Supervisor) currentSpaceEgress(w *worker) spaceEgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spaceEgress(w)
}

// refreshUplink finds the uplink again.
func (s *Supervisor) refreshUplink() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshUplinkLocked()
}

// refreshUplinkLocked finds the uplink again, and reports whether it
// changed; the caller holds s.mu. A name the tables couldn't match exactly
// counts as no uplink.
func (s *Supervisor) refreshUplinkLocked() bool {
	up, err := s.opts.Uplink()
	if err == nil && (up.Name == "" || len(up.Name) >= unix.IFNAMSIZ || strings.ContainsAny(up.Name, "\x00/ ") || strings.HasPrefix(up.Name, LinkPrefix)) {
		err = fmt.Errorf("uplink %q: %w", up.Name, errUplinkUnusable)
	}
	if err != nil {
		up = egress.Uplink{}
	}
	changed := up != s.uplink
	if changed {
		s.log.Info("uplink", "uplink", up.Name, "ipv4", up.IPv4, "ipv6", up.IPv6, "err", err)
	}
	s.uplink, s.uplinkErr = up, err
	return changed
}

// watchRoutes follows the root namespace's routes: when the default route
// moves (DHCP, a new interface), the uplink is found again and the tables
// follow it.
func (s *Supervisor) watchRoutes() {
	defer close(s.watchDone)
	updates := make(chan netlink.RouteUpdate, 64)
	if err := netlink.RouteSubscribeWithOptions(updates, s.stopWatch, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) { s.log.Warn("route watcher", "err", err) },
	}); err != nil {
		s.log.Warn("not following route changes: the uplink is found again only with SetSpaces", "err", err)
		return
	}
	for {
		select {
		case <-s.stopWatch:
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			if u.Dst != nil {
				if ones, _ := u.Dst.Mask.Size(); ones != 0 {
					continue
				}
			}
			// Let a burst of changes settle.
			time.Sleep(200 * time.Millisecond)
			for len(updates) > 0 {
				<-updates
			}
			s.uplinkMoved()
		}
	}
}

// uplinkMoved rebuilds the tables if the uplink changed.
func (s *Supervisor) uplinkMoved() {
	s.setMu.Lock()
	defer s.setMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	before := s.spaceEgresses()
	was := s.saveEgress()
	changed := s.refreshUplinkLocked()
	s.mu.Unlock()
	if !changed {
		return
	}
	if err := s.applyTables(before); err != nil {
		s.log.Error("the uplink changed, and the tables couldn't follow", "err", err)
		s.restoreEgress(was)
	}
}

// Egress describes the node's egress: its uplink, the families it carries,
// and whether the root namespace forwards them.
func (s *Supervisor) Egress() EgressInfo {
	s.mu.Lock()
	up, err := s.uplink, s.uplinkErr
	s.mu.Unlock()
	on := s.forwarding.on()
	return EgressInfo{Uplink: up.Name, IPv4: up.IPv4, IPv6: up.IPv6, Forwarding4: on[0], Forwarding6: on[1], Err: egressError(err)}
}

// egressBeforeRebuild is what a failed rebuild puts back: the uplink, and
// each worker's egress grant and dials.
type egressBeforeRebuild struct {
	uplink    egress.Uplink
	uplinkErr error
	workers   map[*worker]workerEgress
}

type workerEgress struct {
	grant EgressGrant
	dials []Dial
}

// saveEgress snapshots what a failed rebuild puts back; the caller holds
// s.mu.
func (s *Supervisor) saveEgress() egressBeforeRebuild {
	in := egressBeforeRebuild{uplink: s.uplink, uplinkErr: s.uplinkErr, workers: make(map[*worker]workerEgress, len(s.workers))}
	for _, w := range s.workers {
		grant, dials := w.egressRules()
		in.workers[w] = workerEgress{grant: grant, dials: dials}
	}
	return in
}

// restoreEgress puts back, after a failed rebuild, what the tables are
// built from to what they still enforce. Only that: a config and seeds
// pushed meanwhile stay (the worker has them already; taken back, it would
// drop the seeds only the new map names, and sendSeeds never sends a seed
// twice to one process), and so do the inbound credentials (the worker
// keeps the new map). A worker that restarted meanwhile wired its
// namespace's table for what is being undone: its run loop rewrites it.
func (s *Supervisor) restoreEgress(in egressBeforeRebuild) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wired := s.spaceEgresses()
	s.uplink, s.uplinkErr = in.uplink, in.uplinkErr
	for w, e := range in.workers {
		w.setEgress(e.grant, e.dials)
	}
	for w, e := range wired {
		if s.spaceEgress(w) != e {
			w.signal(w.egressChanged)
		}
	}
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
		// The slot is reused later: none of its flows may carry over.
		if err := flushFlows(w.transit); err != nil {
			s.log.Warn("flushing a space's flows", "space", w.space.String(), "err", err)
		}
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
	var refused []error
	ls = slices.DeleteFunc(slices.Clone(ls), func(l Listener) bool {
		ap, err := netip.ParseAddrPort(l.Address)
		if err == nil && ap.Port() >= MasqueradePorts[0] && ap.Port() <= MasqueradePorts[1] {
			refused = append(refused, fmt.Errorf("supervisor: listener %s: port inside the masquerade range %d-%d", l.Address, MasqueradePorts[0], MasqueradePorts[1]))
			return true
		}
		return false
	})
	changed, err := s.shared.setListeners(context.Background(), ls)
	err = errors.Join(append(refused, err)...)
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
	close(s.stopWatch)
	<-s.watchDone

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
	if err := s.putBackForwarding(); err != nil {
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

// putBackForwarding turns off the root's forwarding the supervisor turned
// on, then removes the isolation tables: never the other way round, or the
// root would forward everything for a moment. A family whose forwarding
// can't be turned off keeps the tables, which forward only the spaces'
// traffic (none, once they are stopped), and its record, so the next
// supervisor adopts it and tries again.
func (s *Supervisor) putBackForwarding() error {
	err := s.forwarding.restore()
	if on := s.forwarding.owned(); on != [2]bool{} {
		return errors.Join(err, fmt.Errorf("forwarding still on (IPv4, IPv6: %v): the isolation tables stay", on))
	}
	return errors.Join(err, removeIsolation())
}
