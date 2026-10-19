package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// RouteTable enforces the rules in the OS routing table (route-table mode,
// routetable.Enforcer): everything but the direct destinations and the
// links' endpoints into the TUN.
type RouteTable interface {
	Enforce(ctx context.Context, w routetable.Want) error
	Status() routetable.Status
	Close() error
}

// RouteTableStatus is how route-table enforcement stands: numbers and
// fixed texts only.
type RouteTableStatus struct {
	// Enforced says the OS routing table holds the rules now; false
	// without a RouteTable, before its first enforcement, and while
	// putting it (back) in place fails, which Error then says
	// (routetable.ErrorApply, routetable.ErrorReapply).
	Enforced bool
	Error    string
	// GuardEnforced says the leak guard is in place (routetable's Guard:
	// what routing can't confine, interface-bound sockets); false without
	// one, and while applying it fails, which GuardError then says
	// (routetable.ErrorGuard, routetable.ErrorGuardUnsupported).
	GuardEnforced bool
	GuardError    string
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

// shrinkRoutes takes out of the OS routing table, before the router's
// table changes, the direct prefixes the newly compiled rules no longer
// send around the tunnel, so they never leave in the clear once the rules
// say otherwise. If that fails it falls back to nothing direct (everything
// into the TUN, where the router drops what it calls direct): fail closed.
// What is still wrong is returned, for the step that grows them back.
func (e *Engine) shrinkRoutes(ctx context.Context) error {
	if e.cfg.RouteTable == nil || e.routesWant == nil || e.ruleTable == nil {
		return nil
	}
	old := e.routesWant.Direct
	gone := old.Minus(e.ruleTable.Direct())
	if gone.IsEmpty() {
		return nil
	}
	w := *e.routesWant
	w.Direct = old.Minus(gone)
	err := e.enforce(ctx, w)
	if err == nil {
		e.routesWant = &w
		return nil
	}
	w.Direct = nil
	ferr := e.enforce(ctx, w)
	// The route table keeps trying the last Want it was given: that is
	// what the OS holds, or soon will.
	e.routesWant = &w
	if ferr == nil {
		e.warn("route table: removing direct routes failed; nothing goes direct until the next Apply", err)
		return err
	}
	e.warn("route table: removing direct routes failed; destinations the rules no longer send direct still go direct", errors.Join(err, ferr))
	return errors.Join(err, ferr)
}

// growRoutes puts the compiled rules into the OS routing table, after the
// router enforces them.
func (e *Engine) growRoutes(ctx context.Context, shrinkErr error) error {
	if e.cfg.RouteTable == nil || e.ruleTable == nil {
		return nil
	}
	w := routetable.Want{
		TUN:       e.tunName,
		Overlay:   e.networks,
		Direct:    e.ruleTable.Direct(),
		Bypass:    e.endpoints,
		IPv6:      e.mtu > 0 && e.ipv6Off == nil,
		Upstreams: e.upstreams,
	}
	err := e.enforce(ctx, w)
	e.routesWant = &w // the route table keeps trying it
	if err != nil {
		e.note(Event{Kind: EventRouteTableNotEnforced})
		return fmt.Errorf("dataplane: route table: %w", errors.Join(shrinkErr, err))
	}
	return nil
}

// SetDirectUpstreams says which direct DNS upstreams the node's resolver
// asks, so the route table keeps them reachable from the sockets bound to
// the physical interface (routetable.Want.Upstreams: macOS's scoped
// routes). It re-enforces what is in place if they changed; before the
// first Apply they are kept for it.
func (e *Engine) SetDirectUpstreams(ctx context.Context, addrs []netip.AddrPort) error {
	e.serial.Lock()
	defer e.serial.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEngineClosed
	}
	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, func(a, b netip.AddrPort) int { return a.Compare(b) })
	addrs = slices.Compact(addrs)
	if slices.Equal(addrs, e.upstreams) {
		return nil
	}
	e.upstreams = addrs
	if e.cfg.RouteTable == nil || e.routesWant == nil {
		return nil
	}
	w := *e.routesWant
	w.Upstreams = addrs
	err := e.enforce(ctx, w)
	e.routesWant = &w // the route table keeps trying it
	if err != nil {
		return fmt.Errorf("dataplane: route table: %w", err)
	}
	return nil
}

func (e *Engine) routeTableStatus() RouteTableStatus {
	if e.cfg.RouteTable == nil {
		return RouteTableStatus{}
	}
	st := e.cfg.RouteTable.Status()
	return RouteTableStatus{
		Enforced: st.Enforced, Error: st.Error, GuardEnforced: st.GuardEnforced, GuardError: st.GuardError,
		Routes: st.Routes, LastApply: st.LastApply,
		Reapplies: st.Reapplies, RulesAhead: st.RulesAhead, OverlayAhead: st.OverlayAhead,
	}
}

// enforce puts w in place with e.mu let go meanwhile (e.serial keeps
// everything else that changes the engine out).
func (e *Engine) enforce(ctx context.Context, w routetable.Want) error {
	rt := e.cfg.RouteTable
	e.mu.Unlock()
	defer e.mu.Lock()
	return rt.Enforce(ctx, w)
}

// warn logs msg, and err (which may quote the map) at debug level only.
func (e *Engine) warn(msg string, err error) {
	if e.cfg.Log != nil {
		e.cfg.Log.Warn(msg)
	}
	e.debug(msg, "err", err)
}
