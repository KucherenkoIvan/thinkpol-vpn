package safety

import (
	"slices"
	"strings"
	"testing"
)

// Listings as pfctl and scutil print them (shapes from their sources and
// the kit's recorded runs; documentation addresses only).
const (
	pfInfoEnabled = "No ALTQ support in kernel\nALTQ related functions disabled\n" +
		"Status: Enabled for 0 days 01:02:03           Debug: Urgent\n\nState Table                          Total             Rate\n  current entries                        0\n"
	pfInfoDisabled = "Status: Disabled for 0 days 00:00:00           Debug: Urgent\n"
	pfInterfaces   = "en0\nlo (skip)\nlo0 (skip)\nutun3\n"
	pfMainStock    = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
	scutilDNS      = "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.0.2.53\n  if_index : 4 (en0)\n  flags    : Request A records\n  reach    : 0x00020002 (Reachable,Directly Reachable Address)\n"
)

// The core's contract with firewall's readers is pinned here as well as
// in firewall's own tests, so a change there that moves a verdict here
// fails a test FROZEN covers: the missing anchor's answer counts only
// from a pfctl that exited non-zero and in time, alone but for pfctl's
// two exact ALTQ lines, and not cut short; an interface whose name holds
// ALTQ is read; a cut Interfaces listing is unreadable.
func TestTheMacSurfacesReadPfctlAndScutil(t *testing.T) {
	ok := func(stdout string) output { return output{Stdout: []byte(stdout)} }
	missing := "pfctl: DIOCGETRULES: Invalid argument\n"
	cut := strings.Repeat("x", 1<<20) + "\n"
	for _, tc := range []struct {
		name string
		norm func(output) ([]string, error)
		out  output
		want []string
	}{
		{"enabled, its debug level kept", pfStatus, ok(pfInfoEnabled), []string{"Status: Enabled", "Debug: Urgent"}},
		{"disabled", pfStatus, ok(pfInfoDisabled), []string{"Status: Disabled", "Debug: Urgent"}},
		{"no debug level printed", pfStatus, ok("Status: Enabled for 0 days 00:00:01\n"), []string{"Status: Enabled"}},
		{"skips, lo0 included", pfSkips, ok(pfInterfaces), []string{"lo", "lo0"}},
		{"no skips", pfSkips, ok("en0\nutun3\n"), []string{}},
		{"every line of the main rules, one naming ALTQ included", outputLines, ok(pfMainStock + "anchor \"ALTQ-test\" all\n"),
			[]string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`, `anchor "ALTQ-test" all`}},
		{"an anchor that doesn't exist", pfAnchor, output{Code: 1, Stderr: []byte(missing)}, []string{}},
		{"the missing answer beside pfctl's ALTQ chatter", pfAnchor,
			output{Code: 1, Stderr: []byte("No ALTQ support in kernel\n" + missing + "ALTQ related functions disabled\n")}, []string{}},
		{"a listing on exit 0 with the missing answer beside it is its rules", pfAnchor,
			output{Stdout: []byte("block drop out all\n"), Stderr: []byte(missing)}, []string{"block drop out all"}},
		{"an interface named with ALTQ is read", pfSkips, ok("ALTQ0 (skip)\nen0\nALTQ related functions disabled\n"), []string{"ALTQ0"}},
		{"dns without reach", dnsWithoutReach, ok(scutilDNS),
			[]string{"DNS configuration", "resolver #1", "nameserver[0] : 192.0.2.53", "if_index : 4 (en0)", "flags    : Request A records"}},
	} {
		got, err := tc.norm(tc.out)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q %v, want %q", tc.name, got, err, tc.want)
		}
	}
	for name, out := range map[string]output{
		"pfctl failed":      {Code: 1, Stderr: []byte("pfctl: Operation not permitted\n")},
		"no status line":    {Stdout: []byte("State Table\n")},
		"no answer in time": {Code: -1, Err: "pfctl -s info: no answer within 30s"},
	} {
		if got, err := pfStatus(out); err == nil {
			t.Errorf("%s: %q", name, got)
		}
	}
	for name, out := range map[string]output{
		"a failed listing":                     {Code: 1, Stderr: []byte("pfctl: Operation not permitted\n")},
		"the missing answer, but timed out":    {Code: -1, Err: "pfctl: no answer within 30s", Stderr: []byte(missing)},
		"an anchor listing that failed else":   {Code: 1, Stderr: []byte("pfctl: Operation not permitted\n")},
		"the missing answer beside other ALTQ": {Code: 1, Stderr: []byte(missing + "ALTQ is off\n")},
		"the missing answer cut short":         {Code: 1, Stderr: []byte(missing + cut)},
	} {
		if got, err := pfAnchor(out); err == nil {
			t.Errorf("%s read as %q", name, got)
		}
	}
	if got, err := pfSkips(ok("en0\n" + cut + "lo0 (skip)\n")); err == nil {
		t.Errorf("a cut Interfaces listing read as %q", got)
	}
}

// A skip left over is LEFT with the reload to do (REBOOT is the undo's to
// say), and DNS is information only.
func TestASkipLeftOverSaysToReloadAndDNSIsOnlyInformation(t *testing.T) {
	base := &snapshot{Lines: map[string][]string{}}
	for _, sf := range surfaces() {
		if sf.norm != nil {
			base.Lines[sf.name] = []string{}
		}
	}
	base.Lines["pf-info"] = []string{"Status: Enabled"}
	base.Lines["dns"] = []string{"resolver #1"}
	now := &snapshot{Lines: map[string][]string{}}
	for k, v := range base.Lines {
		now.Lines[k] = v
	}
	now.Lines["pf-skip"] = []string{"lo0"}
	now.Lines["dns"] = []string{"resolver #1", "resolver #2"}
	var res Result
	res.addDiffs(diff(surfaces(), base, now))
	if len(res.Left) != 1 || res.Left[0].Surface != "pf-skip" || res.Left[0].Next != nextPfReload || len(res.Info) != 1 {
		t.Fatalf("%+v", res)
	}
}

// pf-skip's precondition, on surfaces read from files: it refuses before
// it runs any pfctl when the loaded rules aren't the baseline's or
// anything is skipped already (loading /etc/pf.conf back would drop it).
func TestPfSkipIsRefusedWhenItsUndoWouldDropSomeonesRules(t *testing.T) {
	dir := tempDir(t)
	file := func(name, data string) surface {
		p := dir + "/" + name
		writeFile(t, p, data)
		return surface{name: name, argv: []string{"/bin/cat", p}, norm: catLines}
	}
	for _, tc := range []struct {
		name, rulesAtBase, rulesNow, skipAtBase, skipNow, want string
	}{
		{"the rules changed since the baseline", pfMainStock, "pass quick all\n", "", "", "pf-rules differs"},
		{"a skip loaded since the baseline", pfMainStock, pfMainStock, "", "lo0\n", "pf-skip differs"},
		{"a skip someone loaded before the run", pfMainStock, pfMainStock, "lo0\n", "lo0\n", "skips [lo0] already"},
		{"no main rules listed at the baseline", "", "", "", "", "listed nothing at the baseline"},
	} {
		h := &host{surfaces: []surface{file("pf-rules", tc.rulesNow), file("pf-nat", ""), file("pf-skip", tc.skipNow)}}
		h.baseline = &snapshot{Lines: map[string][]string{
			"pf-rules": listingLines([]byte(tc.rulesAtBase)), "pf-nat": {}, "pf-skip": listingLines([]byte(tc.skipAtBase)),
		}}
		err := (&pfSkipAction{Iface: "lo"}).pre(t.Context(), h)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// Through the command runner, as a snapshot reads it: pfctl's answer about
// a missing anchor exits 1 and is an empty anchor; any other failure is
// unreadable, never empty.
func TestAMissingAnchorIsEmptyAndNothingElseIs(t *testing.T) {
	sh := func(script string) output { return run(t.Context(), []string{"/bin/sh", "-c", script}, nil) }
	if got, err := pfAnchor(sh(`echo "pfctl: DIOCGETRULES: Invalid argument" >&2; exit 1`)); err != nil || len(got) != 0 {
		t.Errorf("the missing anchor's answer: %q %v", got, err)
	}
	for _, script := range []string{
		`echo "pfctl: Operation not permitted" >&2; exit 1`,
		`echo "pfctl: DIOCGETRULESETS: Invalid argument" >&2; exit 1`,
		`exit 1`,
	} {
		if got, err := pfAnchor(sh(script)); err == nil {
			t.Errorf("%s read as %q", script, got)
		}
	}
}
