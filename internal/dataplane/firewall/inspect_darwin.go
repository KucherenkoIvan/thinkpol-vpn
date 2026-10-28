package firewall

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
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
	case err != nil && AnchorMissing(out.stderr):
		// No such anchor: nothing in it.
	case err != nil:
		r.RulesUnreadable = err.Error()
	default:
		r.Rules, err = parseVerboseRules(out.stdout)
		if err != nil {
			r.Rules, r.RulesUnreadable = nil, err.Error()
		}
	}
	r.Present, r.PresentUnknown = len(r.Rules) > 0, r.RulesUnreadable != ""
	r.Exempt, err = g.listTable(ctx, exemptTable)
	if err != nil && !errors.Is(err, errNoTable) {
		r.Exempt, r.ExemptUnreadable = nil, err.Error()
	}
	if on, err := g.enabled(ctx); err != nil {
		r.PF.EnabledUnreadable = err.Error()
	} else {
		r.PF.Enabled = on
	}
	g.inspectGuardCheck(ctx, r.PF)
	r.PF.Reference, r.PF.ReferenceUnreadable = g.inspectReference(ctx)
	return r
}

// inspectGuardCheck reads what the guard's check reads: the main ruleset
// (its verdict, and its lines up to the hook as the evidence), every name
// pf skips, and the anchors that sort before the guard's.
func (g *IPv6Guard) inspectGuardCheck(ctx context.Context, pf *routetable.PFReport) {
	main, err := g.pf.run(ctx, nil, "-s", "rules")
	if err != nil {
		pf.GuardCheckUnreadable = err.Error()
		return
	}
	if _, err := readLines(main.stdout); err != nil {
		pf.GuardCheckUnreadable = err.Error()
		return
	}
	b, err := g.readBypass(ctx)
	if err != nil {
		pf.GuardCheckUnreadable = err.Error()
		return
	}
	switch hooked(main.stdout) {
	case hookOK:
		pf.GuardCheck = "hooked"
	case hookBypassed:
		pf.GuardCheck = "bypassed"
	default:
		pf.GuardCheck = "missing"
	}
	pf.MainRules, pf.Skipped, pf.AnchorsBefore = mainUpToHook(main.stdout), b.skipped, b.before
}

// inspectReference reads the guard's record (without making its
// directory) and, if it names a reference, whether pf lists it as taken
// by that pid. Only a record of another boot is stale; one that isn't a
// regular file or can't be read is unreadable, said in fixed words (a
// record's content never leaves it: it may hold a token).
func (g *IPv6Guard) inspectReference(ctx context.Context) (*routetable.PFReferenceReport, string) {
	t, state, why, err := g.tokens.peek()
	switch {
	case err != nil:
		return nil, err.Error()
	case state == recordStale && why == staleOtherBoot:
		return &routetable.PFReferenceReport{Stale: true}, ""
	case state == recordStale:
		return nil, "the guard's record: " + string(why)
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
	if t.value != 0 {
		ref.Held = referenced(refs, t) == refOurs
		return ref, ""
	}
	switch n := len(slices.DeleteFunc(slices.Clone(refs), func(r pfReference) bool { return r.pid != t.pid })); n {
	case 0:
	case 1:
		ref.Held = true
	default:
		ref.HeldUnreadable = fmt.Sprintf("pf lists %d references for that pid", n)
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
	ls, err := readLines(b)
	if err != nil {
		return nil, err
	}
	for i, l := range ls {
		n := i + 1
		switch {
		case strings.HasPrefix(l, "["):
			if m := counterLine.FindStringSubmatch(l); m != nil && at == wantCounters {
				r := &out[len(out)-1]
				var errs [4]error
				r.Counted = true
				r.Evaluations, errs[0] = strconv.ParseUint(m[1], 10, 64)
				r.Packets, errs[1] = strconv.ParseUint(m[2], 10, 64)
				r.Bytes, errs[2] = strconv.ParseUint(m[3], 10, 64)
				r.States, errs[3] = strconv.ParseUint(m[4], 10, 64)
				if err := errors.Join(errs[:]...); err != nil {
					return nil, fmt.Errorf("pfctl -s rules -v: line %d: a counter that doesn't fit: %w", n, err)
				}
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
