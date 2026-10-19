//go:build linux && !android

package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The golden files pin the isolation tables' rules: the test applies them
// for a fixed state and compares them, as the kernel reports them via
// nft, with what it reported before. A refactor of the rule builders
// proves this way that it regenerates exactly the same rules. When a
// golden file is missing the test prints what it built and fails, so a
// deliberate rule change is a copy of that block into testdata, reviewed
// in the diff.

// TestIsolationRulesetGolden pins the tables for two slots, one with IPv4
// egress and two dials, one with IPv6 egress and one dial, the supervisor
// owning IPv4's forwarding, an allowed prefix and a flow cap — in both
// accept modes (unboundAccepts is the forged-ICMP tests' negative control).
func TestIsolationRulesetGolden(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	for _, tc := range []struct {
		name    string
		unbound bool
	}{
		{"bound", false}, {"unbound", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetUnboundAccepts(tc.unbound)
			defer SetUnboundAccepts(false)
			s := &Supervisor{opts: Options{
				TransitIPv4:   DefaultTransitIPv4,
				TransitIPv6:   DefaultTransitIPv6,
				EgressAllowed: []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")},
				Log:           slog.New(slog.DiscardHandler),
			}}
			opts, err := s.opts.withDefaults()
			if err != nil {
				t.Fatal(err)
			}
			s.opts = opts
			if err := s.applyIsolation(goldenState(opts)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = removeIsolation() })
			goldenCompare(t, "isolation-"+tc.name+".golden", isolationDump(t))
		})
	}
}

// goldenState is what the tables are built from in the golden test: two
// slots, with egress and dials on both families between them.
func goldenState(opts Options) tableState {
	st := tableState{uplink: "tp-up0", owned: [2]bool{true, false}, maxFlows: 1000}
	slot := func(n int, egress [2]bool, dials ...Dial) {
		t := opts.transit(n)
		st.rules = append(st.rules, slotRule{
			link: linkName(n),
			src:  [2]netip.Addr{t.space[0].Addr(), t.space[1].Addr()},
			gw:   [2]netip.Addr{t.root[0].Addr(), t.root[1].Addr()},
			zone: slotZone(n),
			// Documentation addresses: nothing here is dialed, only rendered.
			dials:  dials,
			egress: egress,
		})
	}
	slot(0, [2]bool{true, false},
		Dial{Address: netip.MustParseAddrPort("192.0.2.7:51820"), Network: "udp"},
		Dial{Address: netip.MustParseAddrPort("198.51.100.9:443"), Network: "tcp"})
	slot(3, [2]bool{false, true},
		Dial{Address: netip.MustParseAddrPort("[2001:db8:9::7]:443"), Network: "tcp"})
	return st
}

// isolationDump is both tables as nft lists them, with what varies between
// identical rule sets (rule handles, counters) normalized away.
func isolationDump(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	for _, tb := range []struct{ fam, name string }{
		{"inet", TableName}, {"arp", ArpTableName},
	} {
		fmt.Fprintf(&b, "table %s %s\n", tb.fam, tb.name)
		out, err := exec.Command("nft", "-j", "list", "table", tb.fam, tb.name).CombinedOutput()
		if err != nil {
			t.Fatalf("nft -j list table %s %s: %v: %s", tb.fam, tb.name, err, out)
		}
		var v any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("parse nft's listing of %s %s: %v", tb.fam, tb.name, err)
		}
		normalizeJSON(v)
		listing, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(listing)
		b.WriteString("\n")
	}
	return b.String()
}

// normalizeJSON drops rule handles (fresh on every apply) and zeroes
// counters (nothing flows in this test).
func normalizeJSON(v any) {
	switch v := v.(type) {
	case map[string]any:
		delete(v, "handle")
		if c, ok := v["counter"].(map[string]any); ok {
			c["packets"], c["bytes"] = 0, 0
		}
		for _, e := range v {
			normalizeJSON(e)
		}
	case []any:
		for _, e := range v {
			normalizeJSON(e)
		}
	}
}

func goldenCompare(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("=== GOLDEN %s ===\n%s=== END ===\n", name, got)
		t.Fatalf("no golden file testdata/%s: copy the block printed above into it and run the test again", name)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("the rules differ from testdata/%s:\n%s", name, got)
	}
}
