package routetable

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The policy routing layout (Linux). Mark is also what link sockets carry
// (SocketControl), so they skip Table.
const (
	// Mark is the firewall mark on the transports' sockets.
	Mark = 0x7470
	// Table holds the tunnel's routes: the defaults into the TUN, an
	// unreachable default behind each, a throw route per direct prefix and
	// per link endpoint.
	Table = 0x7470
	// PriorityLinks looks up the main table, without its default routes,
	// for lookups bound to a physical interface: the kernel resolving the
	// gateway of a route given with its device (a DHCP client's default
	// route, also one inside the overlay's range or on a subnet not
	// mirrored yet), and sockets bound to it, which routing can't keep in
	// the tunnel anyway (the firewall's job).
	PriorityLinks = 5298
	// PriorityOverlay looks the overlay's networks up in Table, before
	// anything else unbound: no route in main (a DHCP server's classless route
	// into the overlay's range, an on-link subnet overlapping it) gets
	// overlay traffic.
	PriorityOverlay = 5299
	// PriorityMain looks up the main table for the subnets the physical
	// interfaces reach on-link inside the local ranges, and nothing else:
	// no other route there (a DHCP server's classless routes, another
	// VPN's, an "on-link" public subnet a hostile network hands out) beats
	// the tunnel.
	PriorityMain = 5300
	// PriorityTunnel sends every packet without Mark to Table; what Table
	// throws, and marked packets, go on to the main table and its
	// physical default route.
	PriorityTunnel = 5301
	// unreachableMetric puts the unreachable routes behind the TUN's, so
	// traffic is dropped whenever the TUN can't take it (no IPv6; for the
	// overlay, the TUN down or gone too).
	unreachableMetric = 2048
)

// Want is what route-table enforcement puts in place.
type Want struct {
	// TUN is the overlay interface: everything not direct goes there.
	TUN string
	// Overlay are the space's overlay networks, looked up in the main
	// table (the TUN's own routes) ahead of everything else.
	Overlay []netip.Prefix
	// Direct are the destinations that go around the tunnel, through the
	// physical default route (the rules' direct set). Nil is none.
	Direct *lists.Set
	// Bypass are the link endpoints: always around the tunnel, so links
	// never loop into it, whatever marks they carry.
	Bypass []netip.Addr
	// IPv6 says the TUN carries IPv6. Without it IPv6 is unreachable but
	// for direct destinations and endpoints: it never leaks around the
	// tunnel.
	IPv6 bool
	// Upstreams are the resolver's direct DNS upstreams. On macOS their
	// sockets are bound to the physical interface (SocketControl), which
	// reaches only what a route on that interface reaches: each gets a
	// route scoped to the interface (one only such sockets use), unless
	// it is on-link. Linux's sockets carry the mark instead: unused there.
	// The guard exempts them too (GuardFor), for an OS without marks: to
	// their port, so they carry it.
	Upstreams []netip.AddrPort
}

// Equal reports whether w and o put the same routes in place.
func (w Want) Equal(o Want) bool {
	return w.TUN == o.TUN && w.IPv6 == o.IPv6 && w.Direct.Equal(o.Direct) &&
		slices.Equal(bypass(w.Bypass), bypass(o.Bypass)) && slices.Equal(prefixes(w.Overlay), prefixes(o.Overlay)) &&
		slices.Equal(upstreams(w.Upstreams), upstreams(o.Upstreams))
}

// upstreams sorts and deduplicates valid upstreams, unmapped and without
// zones (as bypass does their addresses).
func upstreams(aps []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(aps))
	for _, ap := range aps {
		if a := ap.Addr(); a.IsValid() && !a.IsUnspecified() {
			out = append(out, netip.AddrPortFrom(a.Unmap().WithZone(""), ap.Port()))
		}
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return slices.Compact(out)
}

// upstreamAddrs are the addresses of upstreams(aps), each once.
func upstreamAddrs(aps []netip.AddrPort) []netip.Addr {
	var out []netip.Addr
	for _, ap := range upstreams(aps) {
		out = append(out, ap.Addr())
	}
	return slices.Compact(out)
}

func bypass(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.IsValid() && !a.IsUnspecified() {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// prefixes sorts and deduplicates masked, valid prefixes.
func prefixes(ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.IsValid() {
			out = append(out, p.Masked())
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out)
}

// TrustedOnLink is whether one of the physical interfaces' on-link
// subnets keeps its main-table lookup ahead of the tunnel: only one lying
// entirely inside the local ranges (lists.Local: RFC 1918 LANs,
// link-local, ULA) and inside direct, the destinations the rules send
// around the tunnel. Whatever public subnet a network makes "on-link" (a
// DHCP address 1.1.1.50/24, a PPP peer, a router advertisement's prefix:
// TunnelCrack's LocalNet) goes through the tunnel like any other
// destination, and so does a private one the rules tunnel or block: a
// hostile network can't widen what goes direct.
func TrustedOnLink(p netip.Prefix, direct *lists.Set) bool {
	if !p.IsValid() || p.Bits() == 0 {
		return false
	}
	var b lists.Builder
	if b.AddPrefix(p) != nil {
		return false
	}
	set, _ := b.Build()
	return set.Minus(lists.Local()).IsEmpty() && set.Minus(direct).IsEmpty()
}

// TUNUp reports whether s shows w's TUN up, able to hold its routes.
func TUNUp(w Want, s netcfg.Survey) bool {
	for _, l := range s.Links {
		if l.Name == w.TUN {
			return l.Up
		}
	}
	return false
}

func overlaps(p netip.Prefix, among []netip.Prefix) bool {
	for _, q := range among {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}

// PolicyRouting is w as netcfg configuration for Linux, for each family,
// given the OS's routing (s):
//
//	rule 5298: oif <every link but the TUN and lo> lookup main suppress_prefixlength 0
//	rule 5299: to <overlay network> lookup 0x7470
//	rule 5300: to <trusted on-link subnet> lookup main suppress_prefixlength 0
//	rule 5301: not fwmark 0x7470 lookup 0x7470
//	table 0x7470: <overlay network> dev <TUN>    (IPv6 only while the TUN carries it)
//	              unreachable <overlay network> metric 2048
//	              default dev <TUN>              (IPv6 only while the TUN carries it)
//	              unreachable default metric 2048 (IPv4 only while the TUN is down)
//	              throw <direct prefix>, throw <endpoint>
//
// Direct traffic and endpoints are thrown on to the main table, so they
// follow the physical default route wherever it points: nothing here names
// the gateway. Everything else meets the TUN's default or, when the TUN
// can't take it, the unreachable one: it never falls through to the main
// table.
func PolicyRouting(w Want, s netcfg.Survey) netcfg.Config {
	var cfg netcfg.Config
	overlay := prefixes(w.Overlay)
	var onLink []netip.Prefix
	for _, p := range s.OnLink {
		if TrustedOnLink(p, w.Direct) && !overlaps(p, overlay) {
			onLink = append(onLink, p)
		}
	}
	onLink = prefixes(onLink)
	up := TUNUp(w, s)
	for _, f := range []netcfg.Family{netcfg.IPv4, netcfg.IPv6} {
		for _, l := range s.Links {
			if l.Name != w.TUN && l.Name != "lo" {
				cfg.Rules = append(cfg.Rules, netcfg.Rule{Family: f, Priority: PriorityLinks, Oif: l.Name, SuppressDefaultRoutes: true})
			}
		}
		for _, p := range overlay {
			if netcfg.FamilyOf(p.Addr()) == f {
				cfg.Rules = append(cfg.Rules, netcfg.Rule{Family: f, Priority: PriorityOverlay, Dst: p, Table: Table})
			}
		}
		for _, p := range onLink {
			if netcfg.FamilyOf(p.Addr()) == f {
				// Without its default: a subnet whose own route is gone
				// must not find main's default.
				cfg.Rules = append(cfg.Rules, netcfg.Rule{Family: f, Priority: PriorityMain, Dst: p, SuppressDefaultRoutes: true})
			}
		}
		cfg.Rules = append(cfg.Rules, netcfg.Rule{Family: f, Priority: PriorityTunnel, Table: Table, Mark: Mark, Invert: true})
	}
	for _, p := range overlay {
		if up && (p.Addr().Is4() || w.IPv6) {
			cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: p, Interface: w.TUN, Table: Table})
		}
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: p, Type: netcfg.RouteUnreachable, Metric: unreachableMetric, Table: Table})
	}
	thrown := lists.Builder{}
	thrown.AddSet(w.Direct)
	for _, a := range bypass(w.Bypass) {
		_ = thrown.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // an IPv4-mapped endpoint was unmapped
	}
	set, _ := thrown.Build()
	throws := set.Prefixes()
	all4 := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	// (All of IPv4 direct, which the overlay's network never allows, is a
	// throw default instead.) IPv4's unreachable default is there only
	// while the TUN is down: a reject route answers the kernel's gateway
	// lookups for a new interface before the rules for it exist, which
	// the TUN's own default, bound to the TUN, lets through to main.
	switch {
	case slices.Contains(throws, all4):
	case up:
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all4, Interface: w.TUN, Table: Table})
	default:
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all4, Type: netcfg.RouteUnreachable, Metric: unreachableMetric, Table: Table})
	}
	all6 := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	if up && w.IPv6 {
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all6, Interface: w.TUN, Table: Table})
	}
	cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all6, Type: netcfg.RouteUnreachable, Metric: unreachableMetric, Table: Table})
	for _, p := range throws {
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: p, Type: netcfg.RouteThrow, Table: Table})
	}
	return cfg
}

// Enforcer keeps Want in place through a netcfg configurator of
// OwnerRouteTable: it applies each Want it is given, and applies it again
// when Watch reports a change (an interface going down or up, its
// subnets, the physical gateway, someone removing a route or rule of
// ours), every Backstop anyway, and every RetryAfter while that fails.
// Close removes everything. With a Guard, the guard follows the routes at
// each step, with a status of its own: its failure never undoes the
// routes or fails an Enforce.
type Enforcer struct {
	cfg   netcfg.Configurator
	guard Guard // nil: routes only
	log   *slog.Logger
	// now: the clock the warn rate limit reads.
	now func() time.Time

	// enforcing serializes Enforce and Close, which pause the watcher (it
	// re-applies on its own goroutine, never at the same time): so the
	// configurator and the guard are used by one goroutine at a time, and
	// the watcher doesn't wade through an Apply's own tens of thousands of
	// events.
	enforcing sync.Mutex
	closed    bool
	stopWatch context.CancelFunc
	watching  chan struct{} // closed when the watcher has stopped

	// mu guards what Status and the watcher read; never held during an
	// Apply.
	mu   sync.Mutex
	want *Want // last given
	// applied is the last Want whose routes went in: what the OS holds
	// while want's fail (an Apply is all or nothing), and what the guard
	// must match meanwhile.
	applied *Want
	failing bool // the last Apply or re-Apply of want's routes failed
	// unsupported: the OS can't enforce the table at all (a kernel without
	// rule protocols); nothing is retried.
	unsupported bool
	// guardFailing: the guard's last Apply failed (retried every
	// RetryAfter); guardUnsupported: the OS can't hold it (terminal).
	guardFailing, guardUnsupported bool

	status Status

	// The warns of the failures retried every RetryAfter, each limited on
	// its own (warnLimit): the guard's apply, the routes' re-apply, and
	// subscribing to the routes' and the guard's changes.
	guardWarn, reapplyWarn, watchWarn, guardWatchWarn warnLimit
}

// Status is what an Enforcer reports: numbers and fixed texts only.
type Status struct {
	// Enforced says the last Want's routes are in place: false before the
	// first Enforce and while putting them back fails.
	Enforced bool
	// Error says what is wrong with the routes: ErrorApply, ErrorReapply,
	// ErrorUnsupported or ErrorTUNDown (then Enforced is false too); empty
	// otherwise.
	Error string
	// GuardEnforced says the leak guard for the last Want is in place:
	// false without a Guard, before the first Enforce, and while applying
	// it fails.
	GuardEnforced bool
	// GuardError says what is wrong with the guard: ErrorGuard or
	// ErrorGuardUnsupported; empty otherwise (no Guard included).
	GuardError string
	// Routes is how many routes the last applied Want put in Table.
	Routes int
	// LastApply is how long the last successful Apply took.
	LastApply time.Duration
	// Reapplies counts re-Applies after a change or the backstop (most
	// change nothing).
	Reapplies uint64
	// RulesAhead counts what other software has in place that may route
	// around the tunnel and the layout can't override (Layout.Ahead): policy
	// rules before ours (a mesh VPN's, say) on Linux, host routes over
	// tunneled destinations on macOS.
	RulesAhead int
	// OverlayAhead counts foreign host routes inside the overlay's
	// networks that nothing outranks (macOS, Layout.OverlayAhead): a peer's
	// traffic leaves around the tunnel.
	OverlayAhead int
}

// What Status.Error and Status.GuardError say.
const (
	ErrorApply   = "applying the route table failed"
	ErrorReapply = "putting the route table back failed"
	// ErrorUnsupported: the kernel can't hold the table (rules need
	// Linux 4.17 or later); terminal.
	ErrorUnsupported = "the route table needs Linux 4.17 or later"
	// ErrorTUNDown: the TUN is down or gone; everything but direct
	// destinations is unreachable until it is back.
	ErrorTUNDown = "the TUN is down: traffic is blocked until it is back"
	// ErrorGuard: the routes may be in place, the leak guard isn't (or
	// isn't up to date); retried every RetryAfter.
	ErrorGuard = "applying the leak guard failed"
	// ErrorGuardUnsupported: the OS can't hold the leak guard (Linux: no
	// nf_tables; macOS: pf's main ruleset has no `anchor "com.apple/*"`);
	// terminal. Interface-bound sockets aren't confined.
	ErrorGuardUnsupported = "the leak guard is unsupported here: interface-bound sockets aren't confined"
)

const (
	// debounce coalesces a burst of routing events into one re-Apply.
	debounce = 200 * time.Millisecond
	// Backstop re-applies even without an event: one dump of the table,
	// changing nothing when nothing changed.
	Backstop = time.Minute
	// RetryAfter re-applies while the last attempt failed (a TUN that is
	// down can't take its route back).
	RetryAfter = 5 * time.Second
)

// Open starts enforcing routes only through c, which it owns from now on
// (Close closes it). Nothing is in place until the first Enforce.
func Open(c netcfg.Configurator, log *slog.Logger) *Enforcer {
	return OpenWithGuard(c, nil, log)
}

// OpenWithGuard is Open with g enforced along with the routes (nil:
// none); it owns g too.
func OpenWithGuard(c netcfg.Configurator, g Guard, log *slog.Logger) *Enforcer {
	return openWithClock(c, g, log, time.Now)
}

// openWithClock is OpenWithGuard with now as the clock the warn rate
// limit reads.
func openWithClock(c netcfg.Configurator, g Guard, log *slog.Logger, now func() time.Time) *Enforcer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	e := &Enforcer{cfg: c, guard: g, log: log, now: now}
	e.startWatching(false)
	return e
}

// New opens an Enforcer on this host's routing (the calling thread's
// network namespace), with g (nil: none). errors.ErrUnsupported where
// netcfg has no adapter.
func New(g Guard, log *slog.Logger) (*Enforcer, error) {
	c, err := netcfg.New(netcfg.OwnerRouteTable)
	if err != nil {
		return nil, err
	}
	return OpenWithGuard(c, g, log), nil
}

// Clear removes what an Enforcer of this host left (a crash), with
// nothing put in place: for a device that starts without connecting. g
// (nil: none) is a fresh Guard of the host, whose Close removes the
// crashed run's guard, only while this process holds the route table's
// owner lock: whatever keeps netcfg from taking it (another live run,
// or any failure on the way) may mean the guard there is live, so it is
// left alone and the error returned. A Close of the routes that fails
// still lets go of the lock (netcfg.Configurator).
func Clear(g Guard) error {
	return clearWith(func() (netcfg.Configurator, error) { return netcfg.New(netcfg.OwnerRouteTable) }, g)
}

// clearWith is Clear with the owner's configurator from open.
func clearWith(open func() (netcfg.Configurator, error), g Guard) error {
	var held func() error
	if g != nil {
		held = g.Close
	}
	return netcfg.ClearWith(open, held)
}

// startWatching starts the watcher; with check it re-applies first, for
// what changed while it wasn't watching.
func (e *Enforcer) startWatching(check bool) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.stopWatch, e.watching = cancel, done
	go func() {
		defer close(done)
		defer cancel() // a watcher that stops on its own lets go of its subscriptions
		e.watch(ctx, check)
	}()
}

// pauseWatching stops the watcher, letting a re-Apply it started finish.
func (e *Enforcer) pauseWatching() {
	e.stopWatch()
	<-e.watching
}

// Enforce puts w's routes in place, all or nothing: on failure what was
// in place stays, Enforce fails, and the watcher tries w again every
// RetryAfter. The guard, if any, follows routes that went in; its own
// failure doesn't fail Enforce (Status.GuardError says it, and the
// watcher retries it).
func (e *Enforcer) Enforce(ctx context.Context, w Want) error {
	if w.TUN == "" {
		return errors.New("routetable: no TUN")
	}
	e.enforcing.Lock()
	defer e.enforcing.Unlock()
	if e.closed {
		return netcfg.ErrClosed
	}
	e.mu.Lock()
	same := e.want != nil && e.want.Equal(w) && !e.failing && !e.guardFailing
	unsupported := e.unsupported
	e.mu.Unlock()
	if unsupported {
		return fmt.Errorf("routetable: %s: %w", ErrorUnsupported, errors.ErrUnsupported)
	}
	if same {
		return nil
	}
	e.pauseWatching()
	defer e.startWatching(true)
	return e.apply(ctx, w, false)
}

// apply puts w in place against the OS's routing as it is now, then the
// guard for what the routes hold now: w's if they went in, else the last
// applied Want's, which an Apply that failed left in place. The watcher
// is paused or apply runs on it. Only the routes' failure is returned.
func (e *Enforcer) apply(ctx context.Context, w Want, again bool) error {
	start := time.Now()
	s, err := e.cfg.Survey(ctx)
	var l Layout
	if err == nil {
		l = LayoutOf(w, s)
		err = e.cfg.Apply(ctx, l.Config)
	}
	took := time.Since(start)
	if err == nil {
		e.applyGuard(ctx, w)
	} else {
		e.mu.Lock()
		held := e.applied
		e.mu.Unlock()
		if held != nil {
			e.applyGuard(ctx, *held)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.want = &w
	if err == nil {
		e.applied = &w
	}
	e.failing = err != nil
	e.status.Enforced = err == nil
	if again {
		e.status.Reapplies++
	}
	if err != nil {
		e.status.Error = ErrorApply
		if again {
			e.status.Error = ErrorReapply
		}
		if errors.Is(err, errors.ErrUnsupported) {
			e.unsupported, e.status.Error = true, ErrorUnsupported
		}
		return fmt.Errorf("routetable: %w", err)
	}
	e.status.Error = ""
	if !TUNUp(w, s) {
		e.status.Enforced, e.status.Error = false, ErrorTUNDown
	}
	e.status.RulesAhead, e.status.OverlayAhead = l.Ahead, l.OverlayAhead
	if !again || e.status.Routes != len(l.Config.Routes) {
		e.log.Info("route table applied", "routes", len(l.Config.Routes), "took", took.Round(time.Millisecond))
		e.status.LastApply = took
	}
	e.status.Routes = len(l.Config.Routes)
	return nil
}

// applyGuard puts the guard for w in place and says how that went in the
// status; nothing once the OS turned out unable to hold it.
func (e *Enforcer) applyGuard(ctx context.Context, w Want) {
	if e.guard == nil {
		return
	}
	e.mu.Lock()
	unsupported := e.guardUnsupported
	e.mu.Unlock()
	if unsupported {
		return
	}
	err := e.guard.Apply(ctx, GuardFor(w))
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case err == nil:
		e.guardFailing, e.status.GuardEnforced, e.status.GuardError = false, true, ""
		e.guardWarn.reset()
	case errors.Is(err, ErrGuardUnsupported):
		e.guardFailing, e.guardUnsupported = false, true
		e.status.GuardEnforced, e.status.GuardError = false, ErrorGuardUnsupported
		e.log.Warn("route table: the OS can't hold the leak guard; sockets bound to an interface aren't confined", "err", err)
	default:
		e.warnRetry(&e.guardWarn, "route table: applying the leak guard failed, retrying", err.Error())
		e.guardFailing = true
		e.status.GuardEnforced, e.status.GuardError = false, ErrorGuard
	}
}

// Status reports the enforcer's state; it never waits for an Apply.
func (e *Enforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

// Close stops watching and removes everything in place: the guard first,
// then the routes and rules, whose configurator lets go of the owner lock
// last, even when it fails (what it leaves is the owner's next
// configurator's). A second Close returns nil and touches nothing: the
// guard is removed only while the owner lock is held, and after the
// first Close the next run's live guard may be in its place.
func (e *Enforcer) Close() error {
	e.enforcing.Lock()
	defer e.enforcing.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.pauseWatching()
	e.mu.Lock()
	e.want, e.applied, e.status = nil, nil, Status{}
	e.mu.Unlock()
	var err error
	if e.guard != nil {
		err = e.guard.Close()
	}
	return errors.Join(err, e.cfg.Close())
}

// watch re-applies the last Want after each burst of changes Watch
// reports, every Backstop, and every RetryAfter while that fails; and the
// guard alone after each burst of the guard's own Watch.
func (e *Enforcer) watch(ctx context.Context, check bool) {
	var w watches
	e.subscribe(ctx, &w)
	e.subscribeGuard(ctx, &w)
	if check {
		// Subscribed first, so nothing falls between the check and the
		// events.
		if !e.settle(ctx, w.ch) {
			return
		}
		e.reapply(ctx)
	}
	for {
		wait, unsupported := e.backstop()
		if unsupported {
			return // nothing to retry: Close still removes what's left
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.rewatch:
			timer.Stop()
			e.subscribe(ctx, &w)
			continue
		case <-w.regwatch:
			timer.Stop()
			e.subscribeGuard(ctx, &w)
			e.reapplyGuard(ctx) // whatever happened meanwhile
			continue
		case _, ok := <-w.gch:
			timer.Stop()
			if !ok {
				// Events may have been lost: subscribe again, then check.
				e.subscribeGuard(ctx, &w)
			} else if !e.settle(ctx, w.gch) {
				return
			}
			e.reapplyGuard(ctx)
			continue
		case <-timer.C:
		case _, ok := <-w.ch:
			timer.Stop()
			if !ok {
				w.ch, w.rewatch = nil, time.After(RetryAfter)
				continue
			}
			if !e.settle(ctx, w.ch) {
				return
			}
		}
		e.reapply(ctx)
	}
}

// watches are watch's subscriptions: the routes' changes (ch) and the
// guard's (gch), each subscribed again once rewatch or regwatch fires
// after a failure. A nil one is the backstop alone.
type watches struct {
	ch, gch           <-chan struct{}
	rewatch, regwatch <-chan time.Time
}

// subscribe watches the routes' changes, or retries in RetryAfter.
func (e *Enforcer) subscribe(ctx context.Context, w *watches) {
	var err error
	w.ch, err = e.cfg.Watch(ctx)
	switch {
	case errors.Is(err, errors.ErrUnsupported):
		w.ch, w.rewatch = nil, nil // the backstop alone
	case err != nil:
		e.warnRetry(&e.watchWarn, "route table: watching routes failed, retrying", err.Error())
		w.ch, w.rewatch = nil, time.After(RetryAfter)
	default:
		e.watchWarn.reset()
	}
}

// subscribeGuard watches the guard's changes, if there is a guard the OS
// supports, or retries in RetryAfter.
func (e *Enforcer) subscribeGuard(ctx context.Context, w *watches) {
	e.mu.Lock()
	unsupported := e.guardUnsupported
	e.mu.Unlock()
	if e.guard == nil || unsupported {
		w.gch, w.regwatch = nil, nil
		return
	}
	var err error
	w.gch, err = e.guard.Watch(ctx)
	switch {
	case errors.Is(err, errors.ErrUnsupported), errors.Is(err, ErrGuardUnsupported):
		w.gch, w.regwatch = nil, nil // the backstop alone
	case err != nil:
		e.warnRetry(&e.guardWatchWarn, "route table: watching the leak guard failed, retrying", err.Error())
		w.gch, w.regwatch = nil, time.After(RetryAfter)
	default:
		e.guardWatchWarn.reset()
	}
}

// backstop is how long watch waits for a change before it re-applies
// anyway: RetryAfter while the routes or the guard fail, else Backstop;
// unsupported once the table can't be held at all.
func (e *Enforcer) backstop() (wait time.Duration, unsupported bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	wait = Backstop
	if e.failing || e.guardFailing {
		wait = RetryAfter
	}
	return wait, e.unsupported
}

// settle waits until ch is quiet for debounce; false if ctx ended.
func (e *Enforcer) settle(ctx context.Context, ch <-chan struct{}) bool {
	timer := time.NewTimer(debounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case _, ok := <-ch:
			if !ok {
				return true // the watch loop sees it closed and subscribes again
			}
		case <-timer.C:
			return true
		}
	}
}

func (e *Enforcer) reapply(ctx context.Context) {
	e.mu.Lock()
	w, unsupported := e.want, e.unsupported
	e.mu.Unlock()
	if w == nil || unsupported || ctx.Err() != nil {
		return
	}
	switch err := e.apply(ctx, *w, true); {
	case err == nil:
		e.reapplyWarn.reset()
	case ctx.Err() == nil:
		e.warnRetry(&e.reapplyWarn, "route table: putting it back failed, retrying", path.RedactError(err))
	}
}

// reapplyGuard puts the guard back alone, for the routes in place (the
// last applied Want's), whether or not the routes' latest Apply failed:
// a failed Apply leaves the previous routes in place, and they need
// their guard.
func (e *Enforcer) reapplyGuard(ctx context.Context) {
	e.mu.Lock()
	w := e.applied
	e.mu.Unlock()
	if w == nil || ctx.Err() != nil {
		return // no routes in place yet: nothing to guard
	}
	e.applyGuard(ctx, *w)
	e.mu.Lock()
	e.status.Reapplies++
	e.mu.Unlock()
}
