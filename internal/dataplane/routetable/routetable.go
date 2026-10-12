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
	// Table holds the tunnel's routes: the defaults into the TUN, a throw
	// route per direct prefix and per link endpoint.
	Table = 0x7470
	// PriorityMain looks up the main table without its default routes, so
	// the overlay's, the LAN's and every other more specific route there
	// win over Table.
	PriorityMain = 5300
	// PriorityTunnel sends every packet without Mark to Table; what Table
	// throws, and marked packets, go on to the main table and its
	// physical default route.
	PriorityTunnel = 5301
	// unreachableMetric puts IPv6's unreachable default behind the TUN's,
	// so IPv6 is dropped whenever the TUN can't take it.
	unreachableMetric = 2048
)

// Want is what route-table enforcement puts in place.
type Want struct {
	// TUN is the overlay interface: everything not direct goes there.
	TUN string
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

// Routes counts the routes w puts in Table (throws for its direct prefixes
// and endpoints, and the defaults).
func (w Want) Routes() int { return len(Config(w).Routes) }

// Equal reports whether w and o put the same routes in place.
func (w Want) Equal(o Want) bool {
	return w.TUN == o.TUN && w.IPv6 == o.IPv6 && w.Direct.Equal(o.Direct) && slices.Equal(bypass(w.Bypass), bypass(o.Bypass))
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

// Config is w as netcfg configuration, for each family:
//
//	rule 5300: lookup main suppress_prefixlength 0
//	rule 5301: not fwmark 0x7470 lookup 0x7470
//	table 0x7470: default dev <TUN>             (IPv6 only while the TUN carries it)
//	              unreachable default metric 2048 (IPv6)
//	              throw <direct prefix>, throw <endpoint>
//
// Direct traffic and endpoints are thrown back to the main table, so they
// follow the physical default route wherever it points: nothing here names
// the gateway, and a gateway change needs no change here.
func Config(w Want) netcfg.Config {
	var cfg netcfg.Config
	for _, f := range []netcfg.Family{netcfg.IPv4, netcfg.IPv6} {
		cfg.Rules = append(cfg.Rules,
			netcfg.Rule{Family: f, Priority: PriorityMain, SuppressDefaultRoutes: true},
			netcfg.Rule{Family: f, Priority: PriorityTunnel, Table: Table, Mark: Mark, Invert: true},
		)
	}
	thrown := lists.Builder{}
	thrown.AddSet(w.Direct)
	for _, a := range bypass(w.Bypass) {
		_ = thrown.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // an IPv4-mapped endpoint was unmapped
	}
	set, _ := thrown.Build()
	prefixes := set.Prefixes()
	all4 := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	if !slices.Contains(prefixes, all4) {
		// (All of IPv4 direct, which the overlay's network never allows,
		// would be a throw default instead.)
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all4, Interface: w.TUN, Table: Table})
	}
	all6 := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	if w.IPv6 {
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all6, Interface: w.TUN, Table: Table})
	}
	cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: all6, Type: netcfg.RouteUnreachable, Metric: unreachableMetric, Table: Table})
	for _, p := range prefixes {
		cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: p, Type: netcfg.RouteThrow, Table: Table})
	}
	return cfg
}

// Enforcer keeps Want in place through a netcfg configurator of
// OwnerRouteTable: it applies each Want it is given, and applies it again
// when Watch reports a change (the physical gateway moved, or someone
// removed a route or rule of ours). Close removes everything.
type Enforcer struct {
	cfg netcfg.Configurator
	log *slog.Logger

	// enforcing serializes Enforce and Close, which pause the watcher:
	// its own Apply's tens of thousands of events would only slow it.
	enforcing sync.Mutex
	closed    bool
	stopWatch context.CancelFunc
	watching  chan struct{} // closed when the watcher has stopped

	mu     sync.Mutex
	want   *Want // last applied
	status Status
}

// Status is what an Enforcer reports: numbers only.
type Status struct {
	// Routes is how many routes the last applied Want put in Table.
	Routes int
	// LastApply is how long the last successful Apply took.
	LastApply time.Duration
	// Reapplies counts re-Applies after Watch reported a change (most
	// change nothing).
	Reapplies uint64
}

// debounce coalesces a burst of routing events (an Apply's own) into one
// re-Apply.
const debounce = 200 * time.Millisecond

// retryWatch is how long to wait before watching again after Watch failed.
const retryWatch = 5 * time.Second

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

// New opens an Enforcer on this host's routing (the calling thread's
// network namespace). errors.ErrUnsupported where netcfg has no adapter.
func New(log *slog.Logger) (*Enforcer, error) {
	c, err := netcfg.New(netcfg.OwnerRouteTable)
	if err != nil {
		return nil, err
	}
	return Open(c, log), nil
}

// Enforce puts w in place, all or nothing: on failure what was in place
// stays.
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
	same := e.want != nil && e.want.Equal(w)
	e.mu.Unlock()
	if same {
		return nil
	}
	e.pauseWatching()
	defer e.startWatching()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.apply(ctx, w)
}

func (e *Enforcer) apply(ctx context.Context, w Want) error {
	cfg := Config(w)
	start := time.Now()
	if err := e.cfg.Apply(ctx, cfg); err != nil {
		return fmt.Errorf("routetable: %w", err)
	}
	took := time.Since(start)
	e.want = &w
	e.status.Routes, e.status.LastApply = len(cfg.Routes), took
	e.log.Info("route table applied", "routes", len(cfg.Routes), "took", took.Round(time.Millisecond))
	return nil
}

// Status reports the enforcer's state.
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
	defer e.mu.Unlock()
	e.want = nil
	return e.cfg.Close()
}

func (e *Enforcer) watch(ctx context.Context) {
	for {
		ch, err := e.cfg.Watch(ctx)
		if errors.Is(err, errors.ErrUnsupported) {
			e.log.Debug("route table: no watching on this platform")
			return
		}
		if err != nil {
			e.log.Warn("route table: watching routes failed, retrying", "in", retryWatch, "err", err)
		} else {
			e.follow(ctx, ch)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryWatch):
		}
	}
}

// follow re-applies after each burst of changes until ch closes.
func (e *Enforcer) follow(ctx context.Context, ch <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ch:
			if !ok {
				return
			}
		}
		timer := time.NewTimer(debounce)
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case _, ok := <-ch:
				if !ok {
					timer.Stop()
					return
				}
			case <-timer.C:
				waiting = false
			}
		}
		e.reapply(ctx)
	}
}

func (e *Enforcer) reapply(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.want == nil || ctx.Err() != nil {
		return
	}
	e.status.Reapplies++
	start := time.Now()
	if err := e.cfg.Apply(ctx, Config(*e.want)); err != nil {
		if ctx.Err() == nil {
			e.log.Warn("route table: re-applying failed", "err", err)
		}
		return
	}
	e.log.Debug("route table re-applied", "took", time.Since(start).Round(time.Millisecond))
}
