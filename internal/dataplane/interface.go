package dataplane

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"
)

// InterfaceConfigurator sets the overlay interface's addresses, MTU and
// link state (on a node, netcfg's configurator of the overlay's owner).
// Apply converges the interface to c, all or nothing; re-applying the same
// configuration changes nothing. Close removes the addresses it added and
// restores what it changed. Safe for concurrent use.
type InterfaceConfigurator interface {
	Apply(ctx context.Context, c InterfaceConfig) error
	Close() error
}

// InterfaceConfig is the overlay interface's configuration.
type InterfaceConfig struct {
	Name string
	// Addrs are the interface's addresses with their on-link prefix
	// length.
	Addrs []netip.Prefix
	// MTU is set when non-zero; zero leaves the interface's MTU alone.
	MTU int
	// Up brings the interface up; false leaves its state alone.
	Up bool
}

// interfaceTiming paces the interface's re-applies.
type interfaceTiming struct {
	// debounce gathers the link events of one bounce (or a flapping link)
	// into one re-apply, as the route table's watcher does.
	debounce time.Duration
	// cooldown is the least time between two re-applies: events meanwhile
	// wait for it, so a link that keeps changing costs a re-apply per
	// cooldown at most.
	cooldown time.Duration
	// retry re-applies again while the last re-apply failed and the link
	// is up.
	retry time.Duration
}

var defaultInterfaceTiming = interfaceTiming{
	debounce: 200 * time.Millisecond,
	cooldown: time.Second,
	retry:    5 * time.Second,
}

// watchInterface re-applies the overlay interface's configuration whenever
// the TUN's link comes up: Linux drops a TUN's IPv6 addresses when its link
// goes down (and something may have changed its MTU meanwhile), and the
// next map may be far off. A link that is down is left down, and isn't
// retried until it comes up. It stops with Close.
func (e *Engine) watchInterface() {
	defer close(e.interfaceWatched)
	var retry <-chan time.Time
	var coolUntil time.Time
	failing := false
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.router.LinkUp():
			if !e.settleLinkEvents(coolUntil) {
				return
			}
		case <-retry:
		}
		retry = nil
		if e.router.LinkDown() {
			continue // its coming up is the next event
		}
		t := e.timing()
		applied, ifc, err := e.reapplyInterface()
		if !applied {
			continue
		}
		coolUntil = time.Now().Add(t.cooldown)
		if err != nil {
			if !failing {
				e.logger().Warn("overlay interface: re-applying it after a link event failed, retrying while the link is up",
					"in", t.retry, "err", err)
			} else {
				e.debug("overlay interface: re-applying it failed again", "err", err)
			}
			failing = true
			retry = time.After(t.retry)
			continue
		}
		failing = false
		ipv6 := slices.ContainsFunc(ifc.Addrs, func(p netip.Prefix) bool { return p.Addr().Is6() })
		e.logger().Info("overlay interface re-applied", "reason", "link event", "mtu", ifc.MTU, "ipv6", ipv6)
	}
}

// settleLinkEvents lets a burst of link events pass, debounce from the
// first and no earlier than coolUntil; false if the engine closed
// meanwhile.
func (e *Engine) settleLinkEvents(coolUntil time.Time) bool {
	wait := e.timing().debounce
	if d := time.Until(coolUntil); d > wait {
		wait = d
	}
	timer := time.NewTimer(wait)
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
// between Applies, and returns it; applied is false when there was nothing
// to do (no Apply has configured it yet, or the engine is closing).
func (e *Engine) reapplyInterface() (applied bool, ifc InterfaceConfig, err error) {
	e.serial.Lock()
	defer e.serial.Unlock()
	e.mu.Lock()
	cur, closed := e.ifc, e.closed
	e.mu.Unlock()
	if closed || cur == nil || e.ctx.Err() != nil {
		return false, InterfaceConfig{}, nil
	}
	ifc = *cur
	ifc.Up = false // up when the event came; if it went down since, it stays down
	err = e.cfg.Interface.Apply(e.ctx, ifc)
	if e.ctx.Err() != nil {
		return false, InterfaceConfig{}, nil
	}
	if err == nil {
		e.mu.Lock()
		e.ifcReapplies++
		e.mu.Unlock()
	}
	return true, ifc, err
}

func (e *Engine) timing() interfaceTiming {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ifcTiming
}

func (e *Engine) logger() *slog.Logger {
	if e.cfg.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return e.cfg.Log
}
