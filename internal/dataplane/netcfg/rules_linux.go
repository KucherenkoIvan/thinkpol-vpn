//go:build linux && !android

package netcfg

import (
	"context"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ownKernelRules dumps both families' rules carrying our protocol (rules
// take one since Linux 4.17, which netcfg needs for them).
func (c *linuxConfigurator) ownKernelRules() ([]rawRule, error) {
	rules, err := dumpAllRules(c.rules)
	if err != nil {
		return nil, err
	}
	var out []rawRule
	for _, r := range rules {
		if r.protocol == c.proto {
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
	return c.checkAddedRules(added)
}

// errOldKernel is a kernel that drops a rule's protocol (before Linux
// 4.17): its rules can't be told from anyone else's.
var errOldKernel = fmt.Errorf("netcfg: policy rules need Linux 4.17 or later (rule protocols): %w", errors.ErrUnsupported)

// errNotReadBack is a rule just added that the kernel holds, with our
// protocol, as something netcfg doesn't add: an attribute this kernel
// reports that parseRawRule doesn't read, or the rule changed meanwhile.
// Taken as is, every Apply would replace that rule.
var errNotReadBack = errors.New("netcfg: a rule just added doesn't read back as added (an attribute this kernel reports that netcfg doesn't read?)")

// checkAddedRules dumps the rules again and judges the ones just added
// (judgeAdded); the strays of a kernel that dropped our protocol are
// deleted.
func (c *linuxConfigurator) checkAddedRules(added []Rule) error {
	have, err := dumpAllRules(c.rules)
	if err != nil {
		return err
	}
	stray, err := judgeAdded(added, have, c.proto)
	var errs []error
	for _, kr := range stray {
		if err := sendRule(c.rules, unix.RTM_DELRULE, 0, kr.msg); err != nil && !gone(err) {
			errs = append(errs, fmt.Errorf("netcfg: remove stray rule %+v: %w", kr.rule, err))
		}
	}
	return errors.Join(append([]error{err}, errs...)...)
}

// judgeAdded says what the kernel made of the rules just added, from a
// dump (have) taken after: nil when each reads back as added, with proto.
// On a kernel that drops rule protocols they come back without it: those
// are returned to delete, with errOldKernel. A rule held with proto that
// doesn't read as added is errNotReadBack.
func judgeAdded(added []Rule, have []rawRule, proto netlink.RouteProtocol) ([]rawRule, error) {
	if stray := strayRules(added, have, proto); len(stray) > 0 {
		return stray, errOldKernel
	}
	withProto := rulesWith(have, proto)
	for _, r := range added {
		if !withProto[r] {
			return nil, fmt.Errorf("%w: %+v", errNotReadBack, r)
		}
	}
	return nil, nil
}

// rulesWith are the kernel's rules carrying proto that read as a Rule.
func rulesWith(have []rawRule, proto netlink.RouteProtocol) map[Rule]bool {
	out := make(map[Rule]bool)
	for _, kr := range have {
		if r, ok := asRule(kr.rule); ok && kr.protocol == proto {
			out[r] = true
		}
	}
	return out
}

// strayRules are the kernel's rules that are one of added but without
// proto, for each added rule the kernel doesn't hold with proto: what a
// kernel that drops rule protocols made of them.
func strayRules(added []Rule, have []rawRule, proto netlink.RouteProtocol) []rawRule {
	withProto := rulesWith(have, proto)
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
// could have added: one parseRawRule marked Other, or not a lookup.
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
	return r, !hr.Other && hr.Action == "lookup"
}

// addKernelRule adds r; its undo deletes it with the same message, so
// only a lookup with r's fields and our protocol can go.
func (c *linuxConfigurator) addKernelRule(r Rule, u *undoLog) error {
	msg := ruleMsg(r, c.proto)
	if err := sendRule(c.rules, unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, msg); err != nil {
		if exists(err) {
			return fmt.Errorf("%w: rule %+v: the same rule is there already", ErrConflict, r)
		}
		return fmt.Errorf("netcfg: add rule %+v: %w", r, err)
	}
	u.push(func() error {
		if err := sendRule(c.rules, unix.RTM_DELRULE, 0, msg); err != nil && !gone(err) {
			return fmt.Errorf("netcfg: remove rule %+v: %w", r, err)
		}
		return nil
	})
	return nil
}

// delKernelRule deletes the kernel's rule kr by sending its message back;
// its undo adds it back, action and all. An undo that finds such a rule
// there again (EEXIST: one with its selectors, table and action, whoever
// added it) is done.
func (c *linuxConfigurator) delKernelRule(kr rawRule, u *undoLog) error {
	err := sendRule(c.rules, unix.RTM_DELRULE, 0, kr.msg)
	if gone(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("netcfg: remove rule %+v: %w", kr.rule, err)
	}
	u.push(func() error {
		if err := sendRule(c.rules, unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, kr.msg); err != nil && !exists(err) {
			return fmt.Errorf("netcfg: restore rule %+v: %w", kr.rule, err)
		}
		return nil
	})
	return nil
}
