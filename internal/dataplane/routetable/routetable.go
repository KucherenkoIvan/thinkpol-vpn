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
	// PriorityMain looks up the main table for the overlay's networks and
	// the subnets the physical interfaces reach on-link, and nothing else:
	// no other route there (a DHCP server's classless routes, another
	// VPN's) beats the tunnel.
	PriorityMain = 5300
	// PriorityTunnel sends every packet without Mark to Table; what Table
	// throws, and marked packets, go on to the main table and its
	// physical default route.
	PriorityTunnel = 5301
	// unreachableMetric puts the unreachable defaults behind the TUN's,
	// so traffic is dropped whenever the TUN can't take it (down, gone,
	// no IPv6).
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
}

// Equal reports whether w and o put the same routes in place.
func (w Want) Equal(o Want) bool {
	return w.TUN == o.TUN && w.IPv6 == o.IPv6 && w.Direct.Equal(o.Direct) &&
		slices.Equal(bypass(w.Bypass), bypass(o.Bypass)) && slices.Equal(prefixes(w.Overlay), prefixes(o.Overlay))
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

// TrustedOnLink is which of the physical interfaces' on-link subnets keep
// their main-table lookup ahead of the tunnel: those inside the local
// ranges (lists.Local: LANs, link-local, ULA), and other IPv4 subnets of
// /24 or longer and IPv6 ones of /64 or longer. A network's DHCP server
// handing out a huge netmask (an address in 8.0.0.0/8 "on-link") gets
// nothing past the tunnel that way.
func TrustedOnLink(p netip.Prefix) bool {
	if !p.IsValid() || p.Bits() == 0 {
		return false
	}
	var b lists.Builder
	if b.AddPrefix(p) == nil {
		if set, _ := b.Build(); set.Minus(lists.Local()).IsEmpty() {
			return true
		}
	}
	if p.Addr().Is4() {
		return p.Bits() >= 24
	}
	return p.Bits() >= 64
}

// Config is w as netcfg configuration, for each family, given the OS's
// routing (s):
//
//	rule 5300: to <overlay network> lookup main
//	rule 5300: to <trusted on-link subnet> lookup main
//	rule 5301: not fwmark 0x7470 lookup 0x7470
//	table 0x7470: default dev <TUN>              (IPv6 only while the TUN carries it)
//	              unreachable default metric 2048
//	              throw <direct prefix>, throw <endpoint>
//
// Direct traffic and endpoints are thrown on to the main table, so they
// follow the physical default route wherever it points: nothing here names
// the gateway. Everything else meets the TUN's default or, when the TUN
// can't take it, the unreachable one: it never falls through to the main
// table.
func Config(w Want, s netcfg.Survey) netcfg.Config {
	var cfg netcfg.Config
	ahead := prefixes(w.Overlay)
	for _, p := range s.OnLink {
		if TrustedOnLink(p) {
			ahead = append(ahead, p)
		}
	}
	ahead = prefixes(ahead)
	for _, f := range []netcfg.Family{netcfg.IPv4, netcfg.IPv6} {
		for _, p := range ahead {
			if netcfg.FamilyOf(p.Addr()) == f {
				cfg.Rules = append(cfg.Rules, netcfg.Rule{Family: f, Priority: PriorityMain, Dst: p})
			}
		}
		cfg.Rules = append(cfg.Rules, netcfg.Rule{Family: f, Priority: PriorityTunnel, Table: Table, Mark: Mark, Invert: true})
	}
	thrown := lists.Builder{}
	thrown.AddSet(w.Direct)
	for _, a := range bypass(w.Bypass) {
		_ = thrown.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // an IPv4-mapped endpoint was unmapped
	}
	set, _ := thrown.Build()
	throws := set.Prefixes()
	all4 := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if !slices.Contains(throws, all4) {
		// (All of IPv4 direct, which the overlay's network never allows,
		// is a throw default instead.)
		cfg.Routes = append(cfg.Routes,
			netcfg.Route{Dst: all4, Interface: w.TUN, Table: Table},
			netcfg.Route{Dst: all4, Type: netcfg.RouteUnreachable, Metric: unreachableMetric, Table: Table})
	}
	all6 := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	if w.IPv6 {
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
// Close removes everything.
type Enforcer struct {
	cfg netcfg.Configurator
	log *slog.Logger

	// enforcing serializes Enforce and Close, which pause the watcher (it
	// re-applies on its own goroutine, never at the same time): so the
	// configurator is used by one goroutine at a time, and the watcher
	// doesn't wade through an Apply's own tens of thousands of events.
	enforcing sync.Mutex
	closed    bool
	stopWatch context.CancelFunc
	watching  chan struct{} // closed when the watcher has stopped

	// mu guards what Status and the watcher read; never held during an
	// Apply.
	mu      sync.Mutex
	want    *Want // last given
	failing bool  // the last Apply or re-Apply of want failed
	status  Status
}

// Status is what an Enforcer reports: numbers and fixed texts only.
type Status struct {
	// Enforced says the last Want is in place: false before the first
	// Enforce and while putting it back fails.
	Enforced bool
	// Error says what failed while not Enforced: ErrorApply or
	// ErrorReapply; empty otherwise.
	Error string
	// Routes is how many routes the last applied Want put in Table.
	Routes int
	// LastApply is how long the last successful Apply took.
	LastApply time.Duration
	// Reapplies counts re-Applies after a change or the backstop (most
	// change nothing).
	Reapplies uint64
	// RulesAhead counts other software's policy rules that come before
	// ours (a mesh VPN's, say): they may route around the tunnel.
	RulesAhead int
}

// What Status.Error says.
const (
	ErrorApply   = "applying the route table failed"
	ErrorReapply = "putting the route table back failed"
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

// Open starts enforcing through c, which it owns from now on (Close closes
// it). Nothing is in place until the first Enforce.
func Open(c netcfg.Configurator, log *slog.Logger) *Enforcer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	e := &Enforcer{cfg: c, log: log}
	e.startWatching()
	return e
}

// New opens an Enforcer on this host's routing (the calling thread's
// network namespace). errors.ErrUnsupported where netcfg has no adapter.
func New(log *slog.Logger) (*Enforcer, error) {
	c, err := netcfg.New(netcfg.OwnerRouteTable)
	if err != nil {
		return nil, err
	}
	return Open(c, log), nil
}

// Clear removes what an Enforcer of this host left (a crash), with
// nothing put in place: for a device that starts without connecting.
func Clear() error {
	c, err := netcfg.New(netcfg.OwnerRouteTable)
	if err != nil {
		return err
	}
	return c.Close()
}

func (e *Enforcer) startWatching() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.stopWatch, e.watching = cancel, done
	go func() {
		defer close(done)
		e.watch(ctx)
	}()
}

// pauseWatching stops the watcher, letting a re-Apply it started finish.
func (e *Enforcer) pauseWatching() {
	e.stopWatch()
	<-e.watching
}

// Enforce puts w in place, all or nothing: on failure what was in place
// stays, and the watcher tries w again every RetryAfter.
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
	same := e.want != nil && e.want.Equal(w) && !e.failing
	e.mu.Unlock()
	if same {
		return nil
	}
	e.pauseWatching()
	defer e.startWatching()
	return e.apply(ctx, w, false)
}

// apply puts w in place against the OS's routing as it is now; the
// watcher is paused or apply runs on it.
func (e *Enforcer) apply(ctx context.Context, w Want, again bool) error {
	start := time.Now()
	s, err := e.cfg.Survey(ctx)
	var cfg netcfg.Config
	if err == nil {
		cfg = Config(w, s)
		err = e.cfg.Apply(ctx, cfg)
	}
	took := time.Since(start)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.want = &w
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
		return fmt.Errorf("routetable: %w", err)
	}
	e.status.Error = ""
	e.status.RulesAhead = 0
	for _, p := range s.ForeignRules {
		if p < PriorityTunnel {
			e.status.RulesAhead++
		}
	}
	if !again || e.status.Routes != len(cfg.Routes) {
		e.log.Info("route table applied", "routes", len(cfg.Routes), "took", took.Round(time.Millisecond))
		e.status.LastApply = took
	}
	e.status.Routes = len(cfg.Routes)
	return nil
}

// Status reports the enforcer's state; it never waits for an Apply.
func (e *Enforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

// Close stops watching and removes every route and rule in place.
func (e *Enforcer) Close() error {
	e.enforcing.Lock()
	defer e.enforcing.Unlock()
	if !e.closed {
		e.closed = true
		e.pauseWatching()
	}
	e.mu.Lock()
	e.want, e.status = nil, Status{}
	e.mu.Unlock()
	return e.cfg.Close()
}

// watch re-applies the last Want after each burst of changes Watch
// reports, every Backstop, and every RetryAfter while that fails.
func (e *Enforcer) watch(ctx context.Context) {
	var ch <-chan struct{}
	var rewatch <-chan time.Time
	subscribe := func() {
		var err error
		ch, err = e.cfg.Watch(ctx)
		switch {
		case errors.Is(err, errors.ErrUnsupported):
			ch, rewatch = nil, nil // the backstop alone
		case err != nil:
			e.log.Warn("route table: watching routes failed, retrying", "in", RetryAfter, "err", err)
			ch, rewatch = nil, time.After(RetryAfter)
		}
	}
	subscribe()
	for {
		wait := Backstop
		e.mu.Lock()
		if e.failing {
			wait = RetryAfter
		}
		e.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-rewatch:
			timer.Stop()
			subscribe()
			continue
		case <-timer.C:
		case _, ok := <-ch:
			timer.Stop()
			if !ok {
				ch, rewatch = nil, time.After(RetryAfter)
				continue
			}
			if !e.settle(ctx, ch) {
				return
			}
		}
		e.reapply(ctx)
	}
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
	w := e.want
	e.mu.Unlock()
	if w == nil || ctx.Err() != nil {
		return
	}
	if err := e.apply(ctx, *w, true); err != nil && ctx.Err() == nil {
		e.log.Warn("route table: putting it back failed, retrying", "in", RetryAfter, "err", err)
	}
}
