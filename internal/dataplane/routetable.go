package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// RouteTable enforces the rules in the OS routing table (route-table
// mode): everything but the direct destinations and the links' endpoints
// into the TUN. Enforce puts w in place, all or nothing, and keeps trying
// the last w it was given while that fails; Close removes everything.
type RouteTable interface {
	Enforce(ctx context.Context, w RouteTableWant) error
	Status() RouteTableStatus
	Close() error
}

// RouteTableWant is what route-table enforcement puts in place.
type RouteTableWant struct {
	// TUN is the overlay interface: everything not direct goes there.
	TUN string
	// Overlay are the space's overlay networks, routed into the TUN ahead
	// of everything else.
	Overlay []netip.Prefix
	// Direct are the destinations that go around the tunnel, through the
	// physical default route (the rules' direct set). Nil is none.
	Direct *lists.Set
	// Bypass are the link endpoints: always around the tunnel, so links
	// never loop into it.
	Bypass []netip.Addr
	// IPv6 says the TUN carries IPv6. Without it IPv6 is unreachable but
	// for direct destinations and endpoints.
	IPv6 bool
}

// RouteTableStatus is how route-table enforcement stands: numbers and
// codes only.
type RouteTableStatus struct {
	// Enforced says the OS routing table holds the rules now; false
	// without a RouteTable, before its first enforcement, and while
	// putting it (back) in place fails, which Error then says.
	Enforced bool
	Error    RouteTableError
	// GuardEnforced says the leak guard is in place (what routing can't
	// confine, interface-bound sockets); false without one, and while
	// applying it fails, which GuardError then says.
	GuardEnforced bool
	GuardError    RouteTableError
	// Routes is how many routes the tunnel's table holds, LastApply how
	// long putting the last change in place took, Reapplies how often a
	// routing change (a link, a gateway, an outside removal) or the
	// backstop had it checked.
	Routes    int
	LastApply time.Duration
	Reapplies uint64
	// RulesAhead counts other software's policy rules ahead of the
	// tunnel's (a mesh VPN's): they may route traffic around it.
	RulesAhead int
	// OverlayAhead counts foreign host routes over overlay addresses the
	// table can't outrank (macOS): those peers' traffic leaves in the
	// clear.
	OverlayAhead int
}

// RouteTableError says what is wrong with the OS routing table or its
// leak guard (RouteTableStatus): a code; the log has the detail.
type RouteTableError string

const (
	RouteTableApplyFailed   RouteTableError = "apply_failed"   // putting the rules in place failed
	RouteTableReapplyFailed RouteTableError = "reapply_failed" // putting them back failed
	RouteTableUnsupported   RouteTableError = "unsupported"    // the OS can't hold them
	RouteTableTUNDown       RouteTableError = "tun_down"       // the TUN is down: traffic is blocked
	GuardFailed             RouteTableError = "guard_failed"   // applying the leak guard failed
	// GuardUnsupported: the OS can't hold the leak guard; interface-bound
	// sockets aren't confined.
	GuardUnsupported RouteTableError = "guard_unsupported"
)

// endpointsOf are the addresses the node dials its links on.
func endpointsOf(pc PathConfig) []netip.Addr {
	var out []netip.Addr
	for _, l := range pc.Table.Links {
		for _, ep := range l.Endpoints {
			if ap, err := netip.ParseAddrPort(ep.Address); err == nil {
				out = append(out, ap.Addr().Unmap())
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// osRoutes is the engine's side of the OS routing table: its RouteTable
// (nil leaves the OS routing alone) and the last Want it was given. It
// keeps one order: the direct routes shrink before the router's table
// changes and grow after (around), so a destination the rules stop
// sending direct never leaves in the clear meanwhile.
type osRoutes struct {
	table RouteTable
	want  *RouteTableWant
	// mu is the engine's, let go while the table changes; warn logs.
	mu   *sync.Mutex
	warn func(msg string, err error)
}

// around changes the router's table (change, failing at the step it
// returns) between shrinking the OS table's direct routes to what direct
// keeps and putting want in place, read once change is done.
func (o *osRoutes) around(ctx context.Context, direct *lists.Set, change func() (Step, error), want func() RouteTableWant) (Step, error) {
	shrinkErr := o.shrink(ctx, direct)
	if step, err := change(); err != nil {
		return step, err
	}
	if err := o.grow(ctx, want(), shrinkErr); err != nil {
		return StepRouteTable, err
	}
	return "", nil
}

// shrink takes out of the OS routing table the direct prefixes direct no
// longer holds. If that fails it falls back to nothing direct (everything
// into the TUN, where the router drops what it calls direct): fail
// closed. What is still wrong is returned, for grow.
func (o *osRoutes) shrink(ctx context.Context, direct *lists.Set) error {
	if o.table == nil || o.want == nil {
		return nil
	}
	old := o.want.Direct
	gone := old.Minus(direct)
	if gone.IsEmpty() {
		return nil
	}
	w := *o.want
	w.Direct = old.Minus(gone)
	err := o.enforce(ctx, w)
	if err == nil {
		o.want = &w
		return nil
	}
	w.Direct = nil
	ferr := o.enforce(ctx, w)
	// The route table keeps trying the last Want it was given: that is
	// what the OS holds, or soon will.
	o.want = &w
	if ferr == nil {
		o.warn("route table: removing direct routes failed; nothing goes direct until the next Apply", err)
		return err
	}
	o.warn("route table: removing direct routes failed; destinations the rules no longer send direct still go direct", errors.Join(err, ferr))
	return errors.Join(err, ferr)
}

// grow puts w, the compiled rules, into the OS routing table.
func (o *osRoutes) grow(ctx context.Context, w RouteTableWant, shrinkErr error) error {
	if o.table == nil {
		return nil
	}
	err := o.enforce(ctx, w)
	o.want = &w // the route table keeps trying it
	if err != nil {
		return fmt.Errorf("dataplane: route table: %w", errors.Join(shrinkErr, err))
	}
	return nil
}

func (o *osRoutes) status() RouteTableStatus {
	if o.table == nil {
		return RouteTableStatus{}
	}
	return o.table.Status()
}

// enforce puts w in place with mu let go meanwhile (the engine's serial
// keeps everything else that changes it out).
func (o *osRoutes) enforce(ctx context.Context, w RouteTableWant) error {
	o.mu.Unlock()
	defer o.mu.Lock()
	return o.table.Enforce(ctx, w)
}

// routeTableWant is what the OS routing table should hold for what runs
// now.
func (e *Engine) routeTableWant() RouteTableWant {
	return RouteTableWant{
		TUN:     e.tunName,
		Overlay: e.networks,
		Direct:  e.ruleTable.Direct(),
		Bypass:  e.endpoints,
		IPv6:    e.mtu > 0 && e.ipv6Off == nil,
	}
}

// warn logs msg, and err (which may quote the map) at debug level only.
func (e *Engine) warn(msg string, err error) {
	if e.cfg.Log != nil {
		e.cfg.Log.Warn(msg)
	}
	e.debug(msg, "err", err)
}
