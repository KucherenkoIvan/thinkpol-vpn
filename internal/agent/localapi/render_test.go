package localapi

import (
	"fmt"
	"strings"
	"testing"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// The rule preset line says whether the data plane enforces the preset:
// not yet while disconnected, nor while laying it out is retried.
func TestTheRulePresetLineSaysWhetherItIsEnforced(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   *localapiv1.Status
		want string
	}{
		{"enforced", &localapiv1.Status{RulePreset: "everything", RulesEnforced: true, DataPlane: &localapiv1.DataPlane{}}, "rule preset:\teverything\n"},
		{"disconnected", &localapiv1.Status{RulePreset: "everything"}, "rule preset:\teverything (applies once connected)\n"},
		{"layout retried", &localapiv1.Status{RulePreset: "everything", DataPlane: &localapiv1.DataPlane{}},
			"rule preset:\teverything (not enforced yet: laying out its routes failed, retrying)\n"},
		{"unavailable", &localapiv1.Status{RulePreset: "everything", RulesEnforced: true, RulePresetUnavailable: true, DataPlane: &localapiv1.DataPlane{}},
			"rule preset:\teverything (unavailable in this space: failing closed)\n"},
	} {
		var b strings.Builder
		line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
		tc.st.Mode = localapiv1.Mode_MODE_SERVER // the preset line alone
		writeDeviceSettings(line, tc.st)
		if b.String() != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, b.String(), tc.want)
		}
	}
}
