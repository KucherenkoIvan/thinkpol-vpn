//go:build linux && !android

package dns

import (
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Queries to an exit leave through the overlay interface or not at all:
// bound to an interface without a route to the exit's address, they
// fail rather than take another way.
func TestTunnelQueriesLeaveThroughTheirInterfaceOnly(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	if out, err := exec.Command("ip", "link", "add", "tpdns0", "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "tpdns0").Run() })
	if out, err := exec.Command("ip", "link", "set", "tpdns0", "up").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, tc := range []struct {
		ifc     string
		answers bool
	}{{"lo", true}, {"tpdns0", false}} {
		f := newFixture(t, Options{TunnelControl: BindToInterface(tc.ifc), Timeout: 500 * time.Millisecond})
		r := f.ask(t, "udp", "foreign.example.", dns.TypeA)
		if got := slices.Equal(answers(r), []string{"203.0.113.1"}); got != tc.answers {
			t.Errorf("bound to %s: %v %v", tc.ifc, dns.RcodeToString[r.Rcode], answers(r))
		}
		if tc.answers {
			continue
		}
		if n := len(f.exit.names()); n != 0 {
			t.Errorf("bound to %s, the exit was asked anyway", tc.ifc)
		}
	}
}
