package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// InspectIPv6Guard reads the guard as pf holds it, for diagnostics: the
// anchor's rules with their counters, its exempt table, how the main
// ruleset reaches it, pf's enabled state, and the reference the guard's
// record names and whether pf still holds it. It only reads: every pfctl
// run is a listing, and the record's directory is opened, never made. It
// works whether or not a guard runs.
func InspectIPv6Guard(ctx context.Context) routetable.GuardReport {
	return newIPv6Guard(execPfctl{path: pfctlPath, timeout: pfctlTimeout}, tokenStore{dir: netcfg.StateDir, boot: trusteddir.BootSession}, guardPoll, hostAddrs).inspect(ctx)
}

func (g *IPv6Guard) inspect(ctx context.Context) routetable.GuardReport {
	r := routetable.GuardReport{Where: "pf anchor " + GuardAnchor, PF: &routetable.PFReport{}}
	out, err := g.pf.run(ctx, nil, "-a", GuardAnchor, "-s", "rules", "-v")
	switch {
	case errors.Is(err, routetable.ErrGuardUnsupported):
		return routetable.GuardReport{Where: r.Where, Unreadable: err.Error()}
	case err != nil && invalidArgument(out):
		// No such anchor: nothing in it.
	case err != nil:
		r.RulesUnreadable = err.Error()
	default:
		r.Rules, err = parseVerboseRules(out.stdout)
		if err != nil {
			r.Rules, r.RulesUnreadable = nil, err.Error()
		}
	}
	r.Present = len(r.Rules) > 0
	r.Exempt, err = g.listTable(ctx, exemptTable)
	if err != nil && !errors.Is(err, errNoTable) {
		r.Exempt, r.ExemptUnreadable = nil, err.Error()
	}
	if on, err := g.enabled(ctx); err != nil {
		r.PF.EnabledUnreadable = err.Error()
	} else {
		r.PF.Enabled = on
	}
	r.PF.Hook, r.PF.Skipped, r.PF.AnchorsBefore, r.PF.HookUnreadable = g.inspectHook(ctx)
	r.PF.Reference, r.PF.ReferenceUnreadable = g.inspectReference(ctx)
	return r
}

// inspectHook reads how the main ruleset reaches the anchor (hooked), and
// what lets IPv6 past it (checkBypass's other two): the interfaces pf
// skips but lo0 (the TUN's among them, which the anchor passes anyway),
// and the anchors that sort before the guard's.
func (g *IPv6Guard) inspectHook(ctx context.Context) (hook string, skips, before []string, unreadable string) {
	main, err := g.pf.run(ctx, nil, "-s", "rules")
	if err != nil {
		return "", nil, nil, err.Error()
	}
	switch hooked(main.stdout) {
	case hookOK:
		hook = "ok"
	case hookBypassed:
		hook = "bypassed"
	default:
		hook = "missing"
	}
	ifcs, err := g.pf.run(ctx, nil, "-s", "Interfaces", "-v")
	if err != nil {
		return "", nil, nil, err.Error()
	}
	anchors, err := g.pf.run(ctx, nil, "-a", appleAnchor, "-s", "Anchors")
	if err != nil && !invalidArgument(anchors) {
		return "", nil, nil, err.Error()
	}
	return hook, skipped(ifcs.stdout, ""), anchorsBefore(anchors.stdout), ""
}

// inspectReference reads the guard's record (without making its
// directory) and, if it names a reference, whether pf lists it as taken
// by that pid.
func (g *IPv6Guard) inspectReference(ctx context.Context) (*routetable.PFReferenceReport, string) {
	t, state, err := g.tokens.peek()
	switch {
	case err != nil:
		return nil, err.Error()
	case state == recordStale:
		return &routetable.PFReferenceReport{Stale: true}, ""
	case state == recordNone:
		return &routetable.PFReferenceReport{}, ""
	}
	ref := &routetable.PFReferenceReport{Recorded: true, Pid: t.pid, PidOnly: t.value == 0}
	refs, understood, err := g.references(ctx)
	switch {
	case err != nil:
		ref.HeldUnreadable = err.Error()
		return ref, ""
	case !understood:
		ref.HeldUnreadable = "pfctl -s References: a listing this agent can't read"
		return ref, ""
	}
	if t.value == 0 {
		_, ref.Held = byPid(refs, t.pid)
	} else {
		ref.Held = referenced(refs, t) == refOurs
	}
	return ref, ""
}

// counterLine is the counters `pfctl -v` prints under each rule:
// "[ Evaluations: 12  Packets: 0  Bytes: 0  States: 0 ]".
var counterLine = regexp.MustCompile(`^\[\s*Evaluations:\s*([0-9]+)\s+Packets:\s*([0-9]+)\s+Bytes:\s*([0-9]+)\s+States:\s*([0-9]+)\s*\]$`)

// insertedLine is the line `pfctl -v` prints under the counters: who
// loaded the rule ("[ Inserted: uid 0 pid 412 ]", with "State Creations:
// N" in some versions).
var insertedLine = regexp.MustCompile(`^\[\s*Inserted:\s*uid\s+[0-9]+\s+pid\s+[0-9]+(\s+State Creations:\s*[0-9]+)?\s*\]$`)

// ruleNumber is the "@N " `pfctl -vv` puts before a rule.
var ruleNumber = regexp.MustCompile(`^@[0-9]+\s+`)

// pfActions are the words a rule pfctl lists starts with.
var pfActions = map[string]bool{
	"pass": true, "block": true, "match": true, "anchor": true, "scrub": true, "nat": true, "rdr": true,
	"binat": true, "no": true, "antispoof": true, "load": true, "nat-anchor": true, "rdr-anchor": true,
	"binat-anchor": true, "scrub-anchor": true, "dummynet": true, "dummynet-anchor": true,
}

// parseVerboseRules reads `pfctl -a <anchor> -s rules -v`: each rule's
// line, then its counters, then optionally who inserted it. Anything else
// (a line that is no rule, counters out of place or unreadable, a rule
// without counters) makes the whole listing unreadable, naming the line:
// half a listing could hide the rule that matters. An empty listing is an
// empty anchor.
func parseVerboseRules(b []byte) ([]routetable.GuardRuleReport, error) {
	var out []routetable.GuardRuleReport
	const (
		wantRule = iota
		wantCounters
		afterCounters
	)
	at := wantRule
	for i, l := range lines(b) {
		n := i + 1
		switch {
		case strings.HasPrefix(l, "["):
			if m := counterLine.FindStringSubmatch(l); m != nil && at == wantCounters {
				r := &out[len(out)-1]
				r.Counted = true
				r.Evaluations, _ = strconv.ParseUint(m[1], 10, 64)
				r.Packets, _ = strconv.ParseUint(m[2], 10, 64)
				r.Bytes, _ = strconv.ParseUint(m[3], 10, 64)
				r.States, _ = strconv.ParseUint(m[4], 10, 64)
				at = afterCounters
				continue
			}
			if insertedLine.MatchString(l) && at == afterCounters {
				at = wantRule
				continue
			}
			return nil, fmt.Errorf("pfctl -s rules -v: line %d: unexpected %q", n, l)
		case at == wantCounters:
			return nil, fmt.Errorf("pfctl -s rules -v: line %d: a rule without counters before it", n)
		}
		text := ruleNumber.ReplaceAllString(l, "")
		if !pfActions[strings.Fields(text)[0]] {
			return nil, fmt.Errorf("pfctl -s rules -v: line %d: not a rule: %q", n, l)
		}
		out = append(out, routetable.GuardRuleReport{Text: text})
		at = wantCounters
	}
	if at == wantCounters {
		return nil, fmt.Errorf("pfctl -s rules -v: the last rule has no counters")
	}
	return out, nil
}
