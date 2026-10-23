package safety

import (
	"slices"
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
		{"skips, lo0 included", pfSkips, ok(pfInterfaces), []string{"lo (skip)", "lo0 (skip)"}},
		{"no skips", pfSkips, ok("en0\nutun3\n"), []string{}},
		{"main rules without ALTQ chatter", pfListing, ok("ALTQ related functions disabled\n" + pfMainStock),
			[]string{`scrub-anchor "com.apple/*" all fragment reassemble`, `anchor "com.apple/*" all`}},
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
	if got, err := pfListing(output{Code: 1, Stderr: []byte("pfctl: Operation not permitted\n")}); err == nil {
		t.Errorf("a failed listing read as %q", got)
	}
}

// What the restore makes of pf left with TP-096's skip: a reboot, never
// a flush.
func TestASkipLeftOverIsARebootAndDNSOnlyInformation(t *testing.T) {
	base := &Snapshot{Lines: map[string][]string{}}
	for _, sf := range surfaces() {
		if sf.Norm != nil {
			base.Lines[sf.Name] = []string{}
		}
	}
	base.Lines["pf-info"] = []string{"Status: Enabled"}
	base.Lines["dns"] = []string{"resolver #1"}
	now := &Snapshot{Lines: map[string][]string{}}
	for k, v := range base.Lines {
		now.Lines[k] = v
	}
	now.Lines["pf-skip"] = []string{"lo (skip)"}
	now.Lines["dns"] = []string{"resolver #1", "resolver #2"}
	var res Result
	for _, d := range Diff(surfaces(), base, now) {
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
