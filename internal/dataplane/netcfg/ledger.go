//go:build darwin || (linux && !android)

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// undoLog collects the inverse of every change Apply makes, so a failed
// Apply can put everything back. A nil log records nothing (Close).
type undoLog []func() error

func (u *undoLog) push(f func() error) {
	if u != nil {
		*u = append(*u, f)
	}
}

func (u undoLog) run() error {
	var errs []error
	for i := len(u) - 1; i >= 0; i-- {
		if err := u[i](); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// linkState is an interface as the ledger sees it.
type linkState struct {
	name       string
	index, mtu int
	up         bool
}

// linkOps is what the ledger asks of the OS about interfaces and their
// addresses, for one Apply or Close. Errors that mean the interface or
// address is gone satisfy gone; addAddr's for an address that is there
// already satisfies exists.
type linkOps interface {
	// linkByName's error names the interface.
	linkByName(name string) (linkState, error)
	linkByIndex(index int) (linkState, error)
	setMTU(l linkState, mtu int) error
	setUp(l linkState, up bool) error
	// addrs are the addresses of the interface with index, with their
	// prefix lengths. Addresses go by index: an owned address's index is
	// all the ledger keeps of where it was added.
	addrs(index int) ([]netip.Prefix, error)
	addAddr(index int, p netip.Prefix) error
	delAddr(index int, p netip.Prefix) error
}

// ledger is what a configurator changed on interfaces: their MTU and
// state, and the addresses it owns. Routes aren't in it: each OS knows
// its own routes apart (Linux by their protocol, macOS by its record).
type ledger struct {
	changed    map[string]linkChange // interfaces whose MTU or state we changed
	ownedAddrs map[addrKey]int       // owned addresses → index they were added to
}

type linkChange struct {
	index   int
	origMTU int // before our first change
	mtu     int // what we set; 0: MTU untouched
	setUp   bool
}

type addrKey struct {
	link   string
	prefix netip.Prefix
}

func newLedger() ledger {
	return ledger{changed: make(map[string]linkChange), ownedAddrs: make(map[addrKey]int)}
}

// wanted are the interfaces and addresses a config names: release keeps
// what the ledger has of them and gives the rest up.
type wanted struct {
	links map[string]bool
	addrs map[addrKey]bool
}

// configure sets the MTU and state of each interface of ifcs and adds its
// addresses (configureLink, configureAddrs), and returns what ifcs name.
func (l *ledger) configure(ctx context.Context, ops linkOps, ifcs []Interface, u *undoLog) (wanted, error) {
	w := wanted{links: make(map[string]bool), addrs: make(map[addrKey]bool)}
	for _, ifc := range ifcs {
		if err := ctx.Err(); err != nil {
			return w, err
		}
		s, err := ops.linkByName(ifc.Name)
		if err != nil {
			return w, err
		}
		w.links[ifc.Name] = true
		if err := l.configureLink(ops, s, ifc, u); err != nil {
			return w, err
		}
		if err := l.configureAddrs(ops, s.index, ifc, w.addrs, u); err != nil {
			return w, err
		}
	}
	return w, nil
}

// configureLink sets the MTU and brings the link up as asked. Zero values
// leave the link alone; what was changed is restored when the interface
// leaves the config or on Close. The record is under the name the config
// gives (on Linux it may be an altname of s).
func (l *ledger) configureLink(ops linkOps, s linkState, ifc Interface, u *undoLog) error {
	name := ifc.Name
	if ch, ok := l.changed[name]; ok && ch.index != s.index {
		l.dropLinkRecord(name, u) // a recreated interface: earlier changes went with the old one
	}
	if ifc.MTU != 0 && s.mtu != ifc.MTU {
		old := s.mtu
		if err := ops.setMTU(s, ifc.MTU); err != nil {
			return fmt.Errorf("netcfg: MTU %d on %s: %w", ifc.MTU, name, err)
		}
		l.updateLinkRecord(name, s.index, func(ch *linkChange) {
			if ch.mtu == 0 {
				ch.origMTU = old
			}
			ch.mtu = ifc.MTU
		}, u, func() error { return ops.setMTU(s, old) })
	}
	if ifc.Up && !s.up {
		if err := ops.setUp(s, true); err != nil {
			return fmt.Errorf("netcfg: bring %s up: %w", name, err)
		}
		l.updateLinkRecord(name, s.index, func(ch *linkChange) { ch.setUp = true },
			u, func() error { return ops.setUp(s, false) })
	}
	return nil
}

// configureAddrs adds ifc's addresses to the interface with index, adding
// each to want. An address already there is used, not owned.
func (l *ledger) configureAddrs(ops linkOps, index int, ifc Interface, want map[addrKey]bool, u *undoLog) error {
	have, err := ops.addrs(index)
	if err != nil {
		return fmt.Errorf("netcfg: addresses of %s: %w", ifc.Name, err)
	}
	for _, p := range ifc.Addrs {
		k := addrKey{ifc.Name, p}
		want[k] = true
		present, other := findAddr(have, p)
		if other.IsValid() {
			return fmt.Errorf("%w: address %v on %s: it is there as %v", ErrConflict, p, ifc.Name, other)
		}
		switch {
		case present && l.ownsAddr(k, index):
		case present: // someone else's: used, not owned
			if _, recorded := l.ownedAddrs[k]; recorded {
				l.dropAddrRecord(k, u)
			}
		default:
			if err := l.addAddr(ops, k, index, u); err != nil {
				return err
			}
		}
	}
	return nil
}

// release removes the owned addresses and restores the interfaces w
// doesn't keep.
func (l *ledger) release(ops linkOps, w wanted, u *undoLog) error {
	for k, idx := range l.ownedAddrs {
		if w.addrs[k] {
			continue
		}
		have, err := ops.addrs(idx)
		if err != nil && !gone(err) {
			return fmt.Errorf("netcfg: addresses of %s: %w", k.link, err)
		}
		if present, _ := findAddr(have, k.prefix); present {
			if err := l.delAddr(ops, k, idx, u); err != nil {
				return err
			}
		}
		l.dropAddrRecord(k, u)
	}
	for name := range l.changed {
		if !w.links[name] {
			if err := l.restoreLink(ops, name, u); err != nil {
				return err
			}
		}
	}
	return nil
}

// closeAll removes every owned address and restores every interface,
// going on past failures; what fails stays in the ledger.
func (l *ledger) closeAll(ops linkOps) []error {
	var errs []error
	for k, idx := range l.ownedAddrs {
		have, err := ops.addrs(idx)
		if err != nil && !gone(err) {
			errs = append(errs, err)
			continue
		}
		if present, _ := findAddr(have, k.prefix); present {
			if err := l.delAddr(ops, k, idx, nil); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		delete(l.ownedAddrs, k)
	}
	for name := range l.changed {
		if err := l.restoreLink(ops, name, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// restoreLink undoes our MTU and state changes on an interface, each only if
// it still is what we set.
func (l *ledger) restoreLink(ops linkOps, name string, u *undoLog) error {
	ch := l.changed[name]
	s, err := ops.linkByIndex(ch.index)
	if gone(err) || (err == nil && s.name != name) {
		l.dropLinkRecord(name, u)
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: interface %s: %w", name, err)
	}
	if ch.mtu != 0 && s.mtu == ch.mtu && ch.origMTU != ch.mtu {
		if err := ops.setMTU(s, ch.origMTU); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: restore MTU of %s: %w", name, err)
		}
		l.updateLinkRecord(name, ch.index, func(ch *linkChange) { ch.mtu, ch.origMTU = 0, 0 },
			u, func() error { return ops.setMTU(s, s.mtu) })
	}
	if ch.setUp && s.up {
		if err := ops.setUp(s, false); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: bring %s down: %w", name, err)
		}
		l.updateLinkRecord(name, ch.index, func(ch *linkChange) { ch.setUp = false },
			u, func() error { return ops.setUp(s, true) })
	}
	l.dropLinkRecord(name, u)
	return nil
}

// updateLinkRecord records a change made to a link. Its undo reverts the
// change and only then the record, so a failed revert keeps the record.
func (l *ledger) updateLinkRecord(name string, index int, change func(*linkChange), u *undoLog, revert func() error) {
	prev, had := l.changed[name]
	ch := prev
	if !had {
		ch = linkChange{index: index}
	}
	change(&ch)
	l.changed[name] = ch
	u.push(func() error {
		if err := revert(); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: undo a change to %s: %w", name, err)
		}
		l.restoreLinkRecord(name, prev, had)
		return nil
	})
}

func (l *ledger) dropLinkRecord(name string, u *undoLog) {
	prev, had := l.changed[name]
	delete(l.changed, name)
	u.push(func() error { l.restoreLinkRecord(name, prev, had); return nil })
}

func (l *ledger) restoreLinkRecord(name string, ch linkChange, had bool) {
	if had {
		l.changed[name] = ch
	} else {
		delete(l.changed, name)
	}
}

func (l *ledger) ownsAddr(k addrKey, index int) bool {
	idx, ok := l.ownedAddrs[k]
	return ok && idx == index
}

func (l *ledger) addAddr(ops linkOps, k addrKey, index int, u *undoLog) error {
	if err := ops.addAddr(index, k.prefix); err != nil {
		if exists(err) {
			return fmt.Errorf("%w: address %v on %s: %w", ErrConflict, k.prefix, k.link, err)
		}
		return fmt.Errorf("netcfg: add %v to %s: %w", k.prefix, k.link, err)
	}
	prev, had := l.ownedAddrs[k]
	l.ownedAddrs[k] = index
	u.push(func() error {
		if err := ops.delAddr(index, k.prefix); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err) // still there: keep owning it
		}
		l.restoreAddrRecord(k, prev, had)
		return nil
	})
	return nil
}

// delAddr deletes an address that is there; its undo adds it back.
func (l *ledger) delAddr(ops linkOps, k addrKey, index int, u *undoLog) error {
	err := ops.delAddr(index, k.prefix)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove %v from %s: %w", k.prefix, k.link, err)
	}
	u.push(func() error { return ops.addAddr(index, k.prefix) })
	return nil
}

func (l *ledger) dropAddrRecord(k addrKey, u *undoLog) {
	prev, had := l.ownedAddrs[k]
	delete(l.ownedAddrs, k)
	u.push(func() error { l.restoreAddrRecord(k, prev, had); return nil })
}

func (l *ledger) restoreAddrRecord(k addrKey, index int, had bool) {
	if had {
		l.ownedAddrs[k] = index
	} else {
		delete(l.ownedAddrs, k)
	}
}

// findAddr reports whether p is in addrs, or else the same address with
// another prefix length (a conflict: an address has one prefix length).
func findAddr(addrs []netip.Prefix, p netip.Prefix) (present bool, other netip.Prefix) {
	for _, a := range addrs {
		if a == p {
			return true, netip.Prefix{}
		}
		if a.Addr() == p.Addr() {
			other = a
		}
	}
	return false, other
}
