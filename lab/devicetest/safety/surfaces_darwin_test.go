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

func TestTheMacSurfacesReadPfctlAndScutil(t *testing.T) {
	ok := func(stdout string) output { return output{Stdout: []byte(stdout)} }
	for _, tc := range []struct {
		name string
		norm func(output) ([]string, error)
		out  output
		want []string
	}{
		{"enabled", pfStatus, ok(pfInfoEnabled), []string{"Status: Enabled"}},
		{"disabled", pfStatus, ok(pfInfoDisabled), []string{"Status: Disabled"}},
		{"skips, lo0 included", pfSkips, ok(pfInterfaces), []string{"lo", "lo0"}},
		{"no skips", pfSkips, ok("en0\nutun3\n"), []string{}},
		{"every line of the main rules, one naming ALTQ included", pfListing, ok(pfMainStock + "anchor \"ALTQ-test\" all\n"),
			[]string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`, `anchor "ALTQ-test" all`}},
		{"an anchor that doesn't exist", pfAnchor, output{Code: 1, Stderr: []byte("pfctl: DIOCGETRULES: Invalid argument\n")}, []string{}},
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
		"a failed listing":                   {Code: 1, Stderr: []byte("pfctl: Operation not permitted\n")},
		"an anchor listing that timed out":   {Code: -1, Err: "pfctl: no answer within 30s", Stderr: []byte("Invalid argument")},
		"an anchor listing that failed else": {Code: 1, Stderr: []byte("pfctl: Operation not permitted\n")},
	} {
		if got, err := pfAnchor(out); err == nil {
			t.Errorf("%s read as %q", name, got)
		}
	}
}

// What the restore makes of pf left with TP-096's skip: a reboot, never
// a flush.
func TestASkipLeftOverIsARebootAndDNSOnlyInformation(t *testing.T) {
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
	now.Lines["pf-skip"] = []string{"lo"}
	now.Lines["dns"] = []string{"resolver #1", "resolver #2"}
	var res Result
	for _, d := range diff(surfaces(), base, now) {
		if d.Info {
			res.Info = append(res.Info, d)
		} else {
			res.Left = append(res.Left, d)
		}
	}
	if len(res.Left) != 1 || res.Left[0].Surface != "pf-skip" || res.Left[0].Next != nextPfReload || len(res.Info) != 1 {
		t.Fatalf("%+v", res)
	}
	if v := verdict(res); v != Reboot {
		t.Errorf("verdict %s", v)
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
		name, rulesNow, skipAtBase, skipNow, want string
	}{
		{"the rules changed since the baseline", "pass quick all\n", "", "", "pf-rules differs"},
		{"a skip loaded since the baseline", pfMainStock, "", "lo0\n", "pf-skip differs"},
		{"a skip someone loaded before the run", pfMainStock, "lo0\n", "lo0\n", "skips [lo0] already"},
	} {
		h := &host{surfaces: []surface{file("pf-rules", tc.rulesNow), file("pf-nat", ""), file("pf-skip", tc.skipNow)}}
		h.baseline = &snapshot{Lines: map[string][]string{
			"pf-rules": listingLines([]byte(pfMainStock)), "pf-nat": {}, "pf-skip": listingLines([]byte(tc.skipAtBase)),
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
