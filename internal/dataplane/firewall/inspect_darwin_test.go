package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// The fixtures in testdata/pfctl are pfctl's listings as the guard reads
// them. Nothing here ran pfctl: the rules are the guard's own as the fake
// pf lists them (fakeExpand: one rule per list item, ICMPv6 types by
// name, `port = 53`); the `-v` counters and "Inserted" lines are laid out
// as pfctl's source prints them (pfctl_print_rule_counters; some versions
// add "State Creations"); info, References, Interfaces, Anchors and the
// table are the fake's formats, References after the transcripts TP-078's
// review cited. TP-078 and TP-096 recorded no listing verbatim; the
// owner's device run records real ones to replace these.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "pfctl", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseVerboseRules(t *testing.T) {
	rules, err := parseVerboseRules(fixture(t, "rules-v.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// The guard's rules for exempt(t), as pfctl lists them.
	want := fakeExpandAll(guardRules("utun7", upstreamTargets(exempt(t))))
	var texts []string
	for _, r := range rules {
		texts = append(texts, r.Text)
		if !r.Counted || r.Chain != "" {
			t.Errorf("rule %+v", r)
		}
	}
	if !slices.Equal(texts, want) {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(texts, "\n"), strings.Join(want, "\n"))
	}
	if r := rules[1]; r.Evaluations != 5120 || r.Packets != 4210 || r.Bytes != 612344 || r.States != 0 {
		t.Errorf("the utun's counters: %+v", r)
	}
	if r := rules[len(rules)-1]; r.Text != "block return out quick inet6 all" || r.Packets != 9 || r.Bytes != 756 || r.Evaluations != 852 {
		t.Errorf("the block's counters: %+v", r)
	}

	for name, n := range map[string]int{"rules-v-state-creations.txt": 3, "rules-vv-numbered.txt": 2, "rules-v-empty.txt": 0} {
		rules, err := parseVerboseRules(fixture(t, name))
		if err != nil || len(rules) != n {
			t.Errorf("%s: %d rules, %v; want %d", name, len(rules), err, n)
			continue
		}
		for _, r := range rules {
			if !strings.HasPrefix(r.Text, "pass out quick") || !r.Counted || r.Evaluations == 0 {
				t.Errorf("%s: %+v", name, r)
			}
		}
	}

	// A listing with a line the parser can't read is unreadable as a
	// whole, naming the line: half a listing could hide the rule that
	// matters.
	for name, want := range map[string]string{
		"rules-v-truncated-counters.txt": "line 5",
		"rules-v-not-a-rule.txt":         "line 4: not a rule",
		"rules-no-counters.txt":          "line 2: a rule without counters",
	} {
		if rules, err := parseVerboseRules(fixture(t, name)); err == nil || !strings.Contains(err.Error(), want) || rules != nil {
			t.Errorf("%s: %d rules, %v; want an error with %q", name, len(rules), err, want)
		}
	}
	if _, err := parseVerboseRules([]byte("pass out quick inet6 all no state\n")); err == nil {
		t.Error("a last rule without counters read")
	}
}

// fakeExpandAll is the fake pf's listing of rules.
func fakeExpandAll(rules []guardRule) []string {
	var out []string
	for _, r := range rules {
		out = append(out, fakeExpand(r.text)...)
	}
	return out
}

// TestTheOtherFixturesParse runs the guard's other parsers over their
// fixtures.
func TestTheOtherFixturesParse(t *testing.T) {
	if on, err := parseEnabled(fixture(t, "info-enabled.txt")); err != nil || !on {
		t.Errorf("info-enabled: %v, %v", on, err)
	}
	if on, err := parseEnabled(fixture(t, "info-disabled.txt")); err != nil || on {
		t.Errorf("info-disabled: %v, %v", on, err)
	}
	refs, understood := parseReferences(fixture(t, "references.txt"))
	if !understood || len(refs) != 2 || refs[1] != (pfReference{pid: 4130, token: 9000000000000000008}) {
		t.Errorf("references: %+v, %v", refs, understood)
	}
	if refs, understood := parseReferences(fixture(t, "references-odd.txt")); understood || len(refs) != 0 {
		t.Errorf("references-odd: %+v, %v", refs, understood)
	}
	table, err := parseTable(fixture(t, "table-show.txt"))
	if err != nil || !slices.Equal(table, pfxs("2001:db8:e::9/128", "2001:db8:d0::/48", "fe80::/10", "ff02::/16")) {
		t.Errorf("table: %v, %v", table, err)
	}
	if hooked(fixture(t, "main-stock.txt")) != hookOK || hooked(fixture(t, "main-bypassed.txt")) != hookBypassed {
		t.Error("main rulesets misread")
	}
	if got := skipped(fixture(t, "interfaces-v.txt"), ""); !slices.Equal(got, []string{"utun7"}) {
		t.Errorf("skipped %q", got)
	}
	if got := anchorsBefore(fixture(t, "anchors.txt")); len(got) != 0 {
		t.Errorf("anchors before %q", got)
	}
}

// readOnly says what of pfctl's runs since the last forget changed
// anything: inspecting runs only listings.
func readOnly(f *fakePF) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		for _, a := range c {
			switch a {
			case "-f", "-E", "-e", "-X", "-d", "-F", "-k", "-K", "-T":
				if a == "-T" && slices.Contains(c, "show") {
					continue
				}
				return fmt.Errorf("inspecting ran pfctl %s", strings.Join(c, " "))
			}
		}
	}
	if len(f.calls) == 0 {
		return errors.New("inspecting ran no pfctl at all")
	}
	return nil
}

func TestInspectReadsTheGuardAsPfListsIt(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	// No guard yet: pf off, no anchor, no record. Not unreadable: nothing
	// there.
	r.pf.forget()
	got := r.guard().inspect(ctx)
	if got.Unreadable != "" || got.Present || got.Rules != nil || got.RulesUnreadable != "" || got.Exempt != nil || got.ExemptUnreadable != "" {
		t.Fatalf("before: %+v", got)
	}
	if pf := got.PF; pf == nil || pf.Enabled || pf.EnabledUnreadable != "" || pf.Hook != "ok" || pf.Reference == nil || pf.Reference.Recorded {
		t.Fatalf("before: pf %+v", got.PF)
	}
	if err := readOnly(r.pf); err != nil {
		t.Fatal(err)
	}

	g := r.guard()
	e := exempt(t)
	if err := g.Apply(ctx, e); err != nil {
		t.Fatal(err)
	}
	refs := r.pf.references()
	if len(refs) != 1 {
		t.Fatalf("references %v", refs)
	}
	r.pf.set(func(f *fakePF) { f.hits = map[int]uint64{1: 4210, rulesFor - 1: 9} })
	r.pf.forget()
	got = g.inspect(ctx)
	if err := readOnly(r.pf); err != nil {
		t.Fatal(err)
	}
	if got.Unreadable != "" || !got.Present || got.RulesUnreadable != "" || got.ExemptUnreadable != "" || got.Where != "pf anchor com.apple/000.thinkpol" {
		t.Fatalf("applied: %+v", got)
	}
	var texts []string
	for _, rule := range got.Rules {
		texts = append(texts, rule.Text)
	}
	if !slices.Equal(texts, r.pf.anchor(GuardAnchor).rules) || len(texts) != rulesFor {
		t.Fatalf("rules %q", texts)
	}
	if got.Rules[1].Packets != 4210 || got.Rules[rulesFor-1].Packets != 9 || got.Rules[rulesFor-1].Bytes != 9*84 || got.Rules[0].Packets != 0 {
		t.Errorf("counters %+v", got.Rules)
	}
	if !slices.Equal(got.Exempt, tableOf(r.pf.anchor(GuardAnchor), exemptTable)) || len(got.Exempt) < 3 {
		t.Errorf("exempt %v", got.Exempt)
	}
	want := routetable.PFReferenceReport{Recorded: true, Pid: refs[0].pid, Held: true}
	if pf := got.PF; !pf.Enabled || pf.Hook != "ok" || len(pf.Skipped) != 0 || len(pf.AnchorsBefore) != 0 || pf.Reference == nil || *pf.Reference != want ||
		pf.EnabledUnreadable != "" || pf.HookUnreadable != "" || pf.ReferenceUnreadable != "" {
		t.Fatalf("applied: pf %+v, reference %+v", got.PF, got.PF.Reference)
	}

	// A References listing the guard can't read: the record is shown,
	// whether pf holds it is unreadable, never guessed.
	r.pf.set(func(f *fakePF) { f.oddReferences = true })
	if ref := g.inspect(ctx).PF.Reference; ref == nil || !ref.Recorded || ref.Held || !strings.Contains(ref.HeldUnreadable, "can't read") {
		t.Fatalf("an odd References listing: %+v", ref)
	}
	r.pf.set(func(f *fakePF) { f.oddReferences = false })

	// Someone turns pf off and bypasses the hook: the snapshot shows it,
	// the reference recorded but no longer held.
	r.pf.disable()
	r.pf.set(func(f *fakePF) {
		f.main = append([]string{"pass out quick all"}, stockMain...)
		f.skip = []string{"en0"}
	})
	got = g.inspect(ctx)
	if pf := got.PF; pf.Enabled || pf.Hook != "bypassed" || !slices.Equal(pf.Skipped, []string{"en0"}) || !pf.Reference.Recorded || pf.Reference.Held {
		t.Fatalf("disabled: pf %+v, reference %+v", got.PF, got.PF.Reference)
	}

	// An anchor whose listing has a line the parser can't read.
	saved := r.pf.anchor(GuardAnchor)
	odd := saved.clone()
	odd.rules = append(odd.rules, "pfctl: DIOCGETRULE: Device busy")
	r.pf.setAnchor(GuardAnchor, odd)
	if got = g.inspect(ctx); !strings.Contains(got.RulesUnreadable, "not a rule") || got.Rules != nil || got.Present {
		t.Fatalf("an odd listing: %+v", got)
	}
	r.pf.setAnchor(GuardAnchor, saved)

	// A record of an earlier boot holds nothing.
	r.pf.set(func(f *fakePF) { f.main, f.skip = stockMain, nil })
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	r.writeRecord(t, "boot 00000000-0000-4000-8000-000000000000\ntoken 9000000000000000001 pid 4001\n")
	got = g.inspect(ctx)
	if got.Present || got.Rules != nil || got.PF.Reference == nil || !got.PF.Reference.Stale || got.PF.Reference.Recorded {
		t.Fatalf("closed, an old record: %+v, reference %+v", got, got.PF.Reference)
	}
}

func TestInspectMakesNoRecordDirectory(t *testing.T) {
	r := newRig(t)
	r.dir = filepath.Join(r.dir, "not-yet")
	got := r.guard().inspect(context.Background())
	if got.PF.Reference == nil || got.PF.Reference.Recorded || got.PF.ReferenceUnreadable != "" {
		t.Fatalf("%+v", got.PF.Reference)
	}
	if _, err := os.Stat(r.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspecting made %s: %v", r.dir, err)
	}
}

// noPfctl is a host without pfctl.
type noPfctl struct{}

func (noPfctl) run(context.Context, []byte, ...string) (pfOutput, error) {
	return pfOutput{}, fmt.Errorf("%w: /sbin/pfctl: no such file", routetable.ErrGuardUnsupported)
}

func TestInspectWithoutPfctlSaysSo(t *testing.T) {
	g := newIPv6Guard(noPfctl{}, newRig(t).store(), 0, ownAddrs)
	got := g.inspect(context.Background())
	if !strings.Contains(got.Unreadable, "no such file") || got.Present || got.PF != nil || got.Where == "" {
		t.Fatalf("%+v", got)
	}
}
