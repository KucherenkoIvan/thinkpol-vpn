package dataplane

import (
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

const (
	// interfaceDebounce gathers the link events of one bounce (or a
	// flapping link) into one re-apply, as the route table's watcher does.
	interfaceDebounce = 200 * time.Millisecond
	// interfaceRetryAfter re-applies again while the last re-apply failed.
	interfaceRetryAfter = 5 * time.Second
)

// watchInterface re-applies the overlay interface's configuration whenever
// the TUN's link comes up: Linux drops a TUN's IPv6 addresses when its link
// goes down (and something may have changed its MTU meanwhile), and the
// next map may be far off. A link that is down is left down. It stops with
// Close.
func (e *Engine) watchInterface() {
	defer close(e.interfaceWatched)
	var retry <-chan time.Time
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.router.LinkUp():
			if !e.settleLinkEvents() {
				return
			}
		case <-retry:
		}
		retry = nil
		if !e.reapplyInterface() {
			retry = time.After(interfaceRetryAfter)
		}
	}
}

// settleLinkEvents lets a burst of link events pass, interfaceDebounce
// from the first; false if the engine closed meanwhile.
func (e *Engine) settleLinkEvents() bool {
	timer := time.NewTimer(interfaceDebounce)
	defer timer.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return false
		case <-e.router.LinkUp():
		case <-timer.C:
			return true
		}
	}
}

// reapplyInterface applies the interface configuration in place again,
// between Applies; false if that failed.
func (e *Engine) reapplyInterface() bool {
	e.serial.Lock()
	defer e.serial.Unlock()
	e.mu.Lock()
	ifc, closed := e.ifc, e.closed
	e.mu.Unlock()
	if closed || ifc == nil || e.ctx.Err() != nil {
		return true
	}
	again := *ifc
	again.Up = false // up when the event came; if it went down since, it stays down
	err := e.cfg.Interface.Apply(e.ctx, netcfg.Config{Interfaces: []netcfg.Interface{again}})
	if e.ctx.Err() != nil {
		return true
	}
	e.mu.Lock()
	e.ifcReapplies++
	e.mu.Unlock()
	if err != nil {
		e.logger().Warn("overlay interface: re-applying it after a link event failed, retrying",
			"in", interfaceRetryAfter, "err", err)
		return false
	}
	ipv6 := slices.ContainsFunc(ifc.Addrs, func(p netip.Prefix) bool { return p.Addr().Is6() })
	e.logger().Info("overlay interface re-applied", "reason", "link event", "mtu", ifc.MTU, "ipv6", ipv6)
	return true
}

func (e *Engine) logger() *slog.Logger {
	if e.cfg.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return e.cfg.Log
}
