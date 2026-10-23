//go:build linux && !android

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"

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
	var added []Rule
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
		added = append(added, r)
	}
	if len(added) == 0 {
		return nil
	}
	return c.checkRuleProtocol(added)
}

// errOldKernel is a kernel that drops a rule's protocol (before Linux
// 4.17): its rules can't be told from anyone else's.
var errOldKernel = fmt.Errorf("netcfg: policy rules need Linux 4.17 or later (rule protocols): %w", errors.ErrUnsupported)

// checkRuleProtocol makes sure the rules just added came back carrying our
// protocol; on a kernel that dropped it, it deletes them (exactly as the
// kernel holds them) and fails.
func (c *linuxConfigurator) checkRuleProtocol(added []Rule) error {
	have, err := c.ownAndForeignRules()
	if err != nil {
		return err
	}
	stray := strayRules(added, have, uint8(c.proto))
	if len(stray) == 0 {
		return nil
	}
	var errs []error
	for _, kr := range stray {
		if err := c.h.RuleDel(&kr); err != nil && !gone(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(append([]error{errOldKernel}, errs...)...)
}

func (c *linuxConfigurator) ownAndForeignRules() ([]netlink.Rule, error) {
	var out []netlink.Rule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := c.listRules(fam)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

// strayRules are the kernel's rules that are one of added but without
// proto, for each added rule the kernel doesn't hold with proto: what a
// kernel that drops rule protocols made of them.
func strayRules(added []Rule, have []netlink.Rule, proto uint8) []netlink.Rule {
	withProto := make(map[Rule]bool)
	for _, kr := range have {
		if r, ok := ruleOf(kr); ok && kr.Protocol == proto {
			withProto[r] = true
		}
	}
	missing := make(map[Rule]bool)
	for _, r := range added {
		if !withProto[r] {
			missing[r] = true
		}
	}
	var out []netlink.Rule
	for _, kr := range have {
		if r, ok := ruleOf(kr); ok && kr.Protocol != proto && missing[r] {
			out = append(out, kr)
			delete(missing, r) // one each: a foreign twin may be someone else's
		}
	}
	return out
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
		Oif:                   kr.OifName,
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
	if kr.Dst != nil {
		a, ok := netip.AddrFromSlice(kr.Dst.IP)
		ones, _ := kr.Dst.Mask.Size()
		if !ok {
			return Rule{}, false
		}
		if r.Family == IPv4 {
			a = a.Unmap()
		}
		r.Dst = netip.PrefixFrom(a, ones)
	}
	hr := HostRule{Mark: kr.Mark, SuppressPrefixlen: kr.SuppressPrefixlen,
		Other: kr.Src != nil || kr.IifName != "" || kr.Tos != 0 || kr.TunID != 0 || kr.Goto >= 0 || kr.Flow >= 0 ||
			kr.IPProto != 0 || kr.Dport != nil || kr.Sport != nil || kr.UIDRange != nil || kr.SuppressIfgroup >= 0}
	if kr.Mask != nil {
		hr.Mask = *kr.Mask
	}
	return r, plainRule(hr, "")
}

func (c *linuxConfigurator) toNetlinkRule(r Rule) *netlink.Rule {
	nr := netlink.NewRule()
	nr.Family = netlink.FAMILY_V4
	if r.Family == IPv6 {
		nr.Family = netlink.FAMILY_V6
	}
	nr.Priority = r.Priority
	if r.Dst.IsValid() {
		nr.Dst = ipNet(r.Dst)
	}
	nr.OifName = r.Oif
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
		if exists(err) {
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

// plainRule says whether r is a rule netcfg could have added: no selector
// it never sets (r.Other), suppress_prefixlength none or 0, a mark set
// whole (mask 0xffffffff) or none, and a lookup ("" when the reader can't
// tell the action: the configurator, until TP-135). The configurator's
// reconcile and diagnostics share it for the mask, suppress and action
// rules only: which selectors count as never set (r.Other) is still each
// reader's own list, ruleOf's netlink.Rule fields and parseRawRule's
// attribute switch, until TP-135 moves the configurator onto the raw dump
// and the list exists once.
func plainRule(r HostRule, action string) bool {
	return !r.Other && (action == "" || action == "lookup") &&
		(r.SuppressPrefixlen == -1 || r.SuppressPrefixlen == 0) &&
		(r.Mark == 0 && r.Mask == 0 || r.Mark != 0 && r.Mask == math.MaxUint32)
}
