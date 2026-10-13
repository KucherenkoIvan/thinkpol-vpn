package agent

import (
	"os"
	"testing"
)

// Outside the lab, tests never touch the host's routing table or resolver
// configuration (on a Mac, the real ones: macOS has an adapter for both).
func TestMain(m *testing.M) {
	if os.Getenv("THINKPOL_LAB") == "" {
		clearHostRouteTable = func() error { return nil }
		restoreHostDNS = func() error { return nil }
		lockHost = func() (func(), error) { return func() {}, nil }
	}
	os.Exit(m.Run())
}
