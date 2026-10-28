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
func (c *linuxConfigurator) ownKernelRules() ([]rawRule, error) {
	rules, err := dumpBothRules(c.rulesNS)
	if err != nil {
		return nil, err
	}
	var out []rawRule
	for _, r := range rules {
		if r.protocol == uint8(c.proto) {
			out = append(out, r)
		}
	}
	return out, nil
}

// reconcileRules makes our rules exactly want: those the kernel has that
// want doesn't (or that a Rule can't express: another selector or
// action) are deleted, the missing ones added.
func (c *linuxConfigurator) reconcileRules(ctx context.Context, want []Rule, have []rawRule, u *undoLog) error {
	wanted := make(map[Rule]bool, len(want))
	for _, r := range want {
		wanted[r] = true
	}
	present := make(map[Rule]bool, len(have))
	for _, kr := range have {
		r, ok := asRule(kr.rule)
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
	have, err := dumpBothRules(c.rulesNS)
	if err != nil {
		return err
	}
	stray := strayRules(added, have, uint8(c.proto))
	if len(stray) == 0 {
		return nil
	}
	var errs []error
	for _, kr := range stray {
		if err := ruleRequest(c.rulesNS, unix.RTM_DELRULE, 0, kr.msg); err != nil && !gone(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(append([]error{errOldKernel}, errs...)...)
}

// strayRules are the kernel's rules that are one of added but without
// proto, for each added rule the kernel doesn't hold with proto: what a
// kernel that drops rule protocols made of them.
func strayRules(added []Rule, have []rawRule, proto uint8) []rawRule {
	withProto := make(map[Rule]bool)
	for _, kr := range have {
		if r, ok := asRule(kr.rule); ok && kr.protocol == proto {
			withProto[r] = true
		}
	}
	missing := make(map[Rule]bool)
	for _, r := range added {
		if !withProto[r] {
			missing[r] = true
		}
	}
	var out []rawRule
	for _, kr := range have {
		if r, ok := asRule(kr.rule); ok && kr.protocol != proto && missing[r] {
			out = append(out, kr)
			delete(missing, r) // one each: a foreign twin may be someone else's
		}
	}
	return out
}

// asRule reads a kernel rule as a Rule; false if it isn't one netcfg
// could have added (plainRule, with its action).
func asRule(hr HostRule) (Rule, bool) {
	r := Rule{
		Family:                hr.Family,
		Priority:              hr.Priority,
		Dst:                   hr.Dst,
		Oif:                   hr.Oif,
		Table:                 hr.Table,
		Mark:                  hr.Mark,
		Invert:                hr.Invert,
		SuppressDefaultRoutes: hr.SuppressPrefixlen == 0,
	}
	if r.Table == unix.RT_TABLE_MAIN {
		r.Table = 0
	}
	return r, plainRule(hr, hr.Action)
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
// back, action and all.
func (c *linuxConfigurator) delKernelRule(kr rawRule, u *undoLog) error {
	err := ruleRequest(c.rulesNS, unix.RTM_DELRULE, 0, kr.msg)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove rule %+v: %w", kr.rule, err)
	}
	u.push(func() error {
		return ruleRequest(c.rulesNS, unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, kr.msg)
	})
	return nil
}

// plainRule says whether r is a rule netcfg could have added: no selector
// it never sets (r.Other, from parseRawRule's attribute switch, the one
// list of them), suppress_prefixlength none or 0, a mark set whole (mask
// 0xffffffff) or none, and a lookup (action "" leaves the action apart:
// HostRule.Other does). Both readers of the raw dump judge by it: the
// configurator's reconcile with the rule's action, diagnostics without.
func plainRule(r HostRule, action string) bool {
	return !r.Other && (action == "" || action == "lookup") &&
		(r.SuppressPrefixlen == -1 || r.SuppressPrefixlen == 0) &&
		(r.Mark == 0 && r.Mask == 0 || r.Mark != 0 && r.Mask == math.MaxUint32)
}
