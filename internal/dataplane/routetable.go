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

// RouteTableStatus is how route-table enforcement stands: numbers only.
type RouteTableStatus struct {
	// Enforced says the OS routing table holds the rules (a RouteTable,
	// applied at least once).
	Enforced bool
	// Routes is how many routes the tunnel's table holds, LastApply how
	// long putting the last change in place took, Reapplies how often a
	// routing change (a gateway, an outside removal) was answered.
	Routes    int
	LastApply time.Duration
	Reapplies uint64
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
	err := e.cfg.RouteTable.Enforce(ctx, w)
	if err == nil {
		e.routesWant = &w
		return nil
	}
	w.Direct = nil
	ferr := e.cfg.RouteTable.Enforce(ctx, w)
	if ferr == nil {
		e.routesWant = &w
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
		TUN:    e.tunName,
		Direct: e.ruleTable.Direct(),
		Bypass: e.endpoints,
		IPv6:   e.mtu > 0 && e.ipv6Off == nil,
	}
	if err := e.cfg.RouteTable.Enforce(ctx, w); err != nil {
		return fmt.Errorf("dataplane: route table: %w", errors.Join(shrinkErr, err))
	}
	e.routesWant = &w
	return nil
}

func (e *Engine) routeTableStatus() RouteTableStatus {
	if e.cfg.RouteTable == nil || e.routesWant == nil {
		return RouteTableStatus{}
	}
	st := e.cfg.RouteTable.Status()
	return RouteTableStatus{Enforced: true, Routes: st.Routes, LastApply: st.LastApply, Reapplies: st.Reapplies}
}

// warn logs msg, and err (which may quote the map) at debug level only.
func (e *Engine) warn(msg string, err error) {
	if e.cfg.Log != nil {
		e.cfg.Log.Warn(msg)
	}
	e.debug(msg, "err", err)
}
