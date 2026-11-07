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
// still hold what the dead one wrote, then deletes those of its tables
// that are there (none on a node that never served: nothing is asked of
// nftables then). Nothing is touched while a live supervisor holds the
// role (netcfg.ErrBusy), and a veth it can't remove stops it there, the
// forwarding and tables as they were.
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
		var still []string
		for fam, name := range [2]string{"IPv4", "IPv6"} {
			key := strings.ReplaceAll(forwardingKeys[fam], "/", ".")
			switch {
			case left[fam]:
				still = append(still, fmt.Sprintf("%s (%s)", name, key))
			case adopted[fam]:
				undone = append(undone, fmt.Sprintf("the root's %s forwarding (%s) and what turning it on changed", name, key))
			}
		}
		if len(still) > 0 {
			return errors.Join(err, fmt.Errorf("%s forwarding still on: the isolation tables stay", strings.Join(still, " and ")))
		}
		tables, lerr := isolationTables()
		if lerr != nil {
			return errors.Join(err, fmt.Errorf("listing the nftables tables: %w", lerr))
		}
		if rerr := removeTables(tables); rerr != nil {
			return errors.Join(err, rerr)
		}
		for _, t := range tables {
			undone = append(undone, "the nftables table "+tableName(t))
		}
		return err
	})
	if err != nil {
		return undone, fmt.Errorf("supervisor: %w", err)
	}
	return undone, nil
}

// isolationTables are the supervisor's tables that are there now.
func isolationTables() ([]*nftables.Table, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	ts, err := c.ListTables()
	if err != nil {
		return nil, err
	}
	var ours []*nftables.Table
	for _, t := range ts {
		if (t.Family == nftables.TableFamilyINet && t.Name == TableName) ||
			(t.Family == nftables.TableFamilyARP && t.Name == ArpTableName) {
			ours = append(ours, t)
		}
	}
	return ours, nil
}

// removeTables deletes tables in one flush; none touches nothing, so a
// kernel without a family's nf_tables never sees it asked for.
func removeTables(tables []*nftables.Table) error {
	if len(tables) == 0 {
		return nil
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	for _, t := range tables {
		c.DelTable(t)
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: remove the isolation tables: %w", err)
	}
	return nil
}

func tableName(t *nftables.Table) string {
	if t.Family == nftables.TableFamilyARP {
		return "arp " + t.Name
	}
	return "inet " + t.Name
}
