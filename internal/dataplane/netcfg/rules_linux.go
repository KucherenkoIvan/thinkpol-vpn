//go:build linux && !android

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ownKernelRules dumps both families' rules carrying our protocol (rules
// take one since Linux 4.17, which netcfg needs for them).
func (c *linuxConfigurator) ownKernelRules() ([]netlink.Rule, error) {
	var out []netlink.Rule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := c.listRules(fam)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if r.Protocol == uint8(c.proto) {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func (c *linuxConfigurator) listRules(fam int) ([]netlink.Rule, error) {
	var err error
	for range 5 {
		var rules []netlink.Rule
		rules, err = c.h.RuleList(fam)
		if err == nil {
			return rules, nil
		}
		if errors.Is(err, unix.EAFNOSUPPORT) {
			return nil, nil // a kernel without IPv6: no IPv6 rules to own
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	return nil, fmt.Errorf("netcfg: list rules: %w", err)
}

// reconcileRules makes our rules exactly want: those the kernel has that
// want doesn't (or that hold selectors a Rule can't express) are deleted,
// the missing ones added.
func (c *linuxConfigurator) reconcileRules(ctx context.Context, want []Rule, have []netlink.Rule, u *undoLog) error {
	wanted := make(map[Rule]bool, len(want))
	for _, r := range want {
		wanted[r] = true
	}
	present := make(map[Rule]bool, len(have))
	for _, kr := range have {
		r, ok := ruleOf(kr)
		if ok && wanted[r] && !present[r] {
			present[r] = true
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.delKernelRule(kr, u); err != nil {
			return err
		}
	}
	for _, r := range want {
		if present[r] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.addKernelRule(r, u); err != nil {
			return err
		}
		present[r] = true
	}
	return nil
}

// ruleOf reads a kernel rule as a Rule; false if it has more to it than a
// Rule says (another selector, mask or action).
func ruleOf(kr netlink.Rule) (Rule, bool) {
	r := Rule{
		Priority:              kr.Priority,
		Table:                 kr.Table,
		Mark:                  kr.Mark,
		Invert:                kr.Invert,
		SuppressDefaultRoutes: kr.SuppressPrefixlen == 0,
	}
	switch kr.Family {
	case netlink.FAMILY_V4:
		r.Family = IPv4
	case netlink.FAMILY_V6:
		r.Family = IPv6
	default:
		return Rule{}, false
	}
	if r.Table == unix.RT_TABLE_MAIN {
		r.Table = 0
	}
	extra := kr.Src != nil || kr.Dst != nil || kr.IifName != "" || kr.OifName != "" || kr.Tos != 0 ||
		kr.TunID != 0 || kr.Goto >= 0 || kr.Flow >= 0 || kr.IPProto != 0 || kr.Dport != nil ||
		kr.Sport != nil || kr.UIDRange != nil || kr.SuppressIfgroup >= 0 ||
		(kr.SuppressPrefixlen != -1 && kr.SuppressPrefixlen != 0)
	mask := uint32(0)
	if kr.Mask != nil {
		mask = *kr.Mask
	}
	switch {
	case kr.Mark == 0 && mask == 0:
	case kr.Mark != 0 && mask == math.MaxUint32:
	default:
		extra = true
	}
	return r, !extra
}

func (c *linuxConfigurator) toNetlinkRule(r Rule) *netlink.Rule {
	nr := netlink.NewRule()
	nr.Family = netlink.FAMILY_V4
	if r.Family == IPv6 {
		nr.Family = netlink.FAMILY_V6
	}
	nr.Priority = r.Priority
	nr.Table = kernelTable(r.Table)
	nr.Mark = r.Mark
	nr.Invert = r.Invert
	if r.SuppressDefaultRoutes {
		nr.SuppressPrefixlen = 0
	}
	nr.Protocol = uint8(c.proto)
	return nr
}

// addKernelRule adds r; its undo deletes it.
func (c *linuxConfigurator) addKernelRule(r Rule, u *undoLog) error {
	nr := c.toNetlinkRule(r)
	if err := c.h.RuleAdd(nr); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: rule %v: the same rule is there already", ErrConflict, r)
		}
		return fmt.Errorf("netcfg: add rule %v: %w", r, err)
	}
	u.push(func() error {
		if err := c.h.RuleDel(nr); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: remove rule %v: %w", r, err)
		}
		return nil
	})
	return nil
}

// delKernelRule deletes exactly the kernel's rule kr; its undo adds it
// back.
func (c *linuxConfigurator) delKernelRule(kr netlink.Rule, u *undoLog) error {
	err := c.h.RuleDel(&kr)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove rule %v: %w", kr, err)
	}
	u.push(func() error { return c.h.RuleAdd(&kr) })
	return nil
}
