//go:build linux && !android

package supervisor

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// ClearLeftovers undoes what a dead supervisor left in the root namespace,
// as New does when it starts, then what Close would have: for a service
// uninstall, which leaves no next start to do it. While it holds the
// node's supervisor role (Options.NewRoot, whose close removes the routes
// the dead one's configurator recorded) it removes the spaces' veths, puts
// back the forwarding sysctls the record in Options.RuntimeDir names that
// still hold what the dead one wrote, then removes its tables. Nothing is
// touched while a live supervisor holds the role (netcfg.ErrBusy).
//
// The tables stay while any forwarding the dead one turned on stays on,
// or while its record can't be read, so the root still forwards nothing
// but the spaces' (no space is left). It returns what it undid, and as the
// error what it couldn't.
func ClearLeftovers(opts Options) ([]string, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	if opts.NewRoot == nil {
		return nil, errors.New("supervisor: no NewRoot")
	}
	var undone []string
	err = netcfg.ClearWith(opts.NewRoot, func() error {
		links, err := removeStaleLinks(opts.Log)
		for _, l := range links {
			undone = append(undone, "the space link "+l)
		}
		if err != nil {
			return err
		}
		f := rootForwarding{sys: opts.sysctls}
		if err := f.load(opts.RuntimeDir); err != nil {
			return fmt.Errorf("the forwarding record can't be read, so the isolation tables stay: %w", err)
		}
		adopted := f.owned()
		err = f.restore()
		left := f.owned()
		for fam, name := range [2]string{"IPv4", "IPv6"} {
			if adopted[fam] && !left[fam] {
				undone = append(undone, fmt.Sprintf("the root's %s forwarding (%s) and what turning it on changed", name, strings.ReplaceAll(forwardingKeys[fam], "/", ".")))
			}
		}
		if left != [2]bool{} {
			return errors.Join(err, fmt.Errorf("forwarding still on (IPv4, IPv6: %v): the isolation tables stay", left))
		}
		tables, lerr := isolationTables()
		if rerr := removeIsolation(); rerr != nil {
			return errors.Join(err, rerr)
		}
		if lerr == nil {
			for _, t := range tables {
				undone = append(undone, "the nftables table "+t)
			}
		}
		return err
	})
	if err != nil {
		return undone, fmt.Errorf("supervisor: %w", err)
	}
	return undone, nil
}

// isolationTables names the supervisor's tables that are there now.
func isolationTables() ([]string, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	ts, err := c.ListTables()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, t := range ts {
		switch {
		case t.Family == nftables.TableFamilyINet && t.Name == TableName:
			names = append(names, "inet "+t.Name)
		case t.Family == nftables.TableFamilyARP && t.Name == ArpTableName:
			names = append(names, "arp "+t.Name)
		}
	}
	return names, nil
}
