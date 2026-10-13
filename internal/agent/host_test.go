package agent

import (
	"os"
	"testing"
)

// Outside the lab, tests never touch the host's routing table or resolver
// configuration; nowhere do they take the host's agent lock, which belongs
// to the host's own agent (hostlock_unix_test.go locks files of its own).
func TestMain(m *testing.M) {
	if os.Getenv("THINKPOL_LAB") == "" {
		clearHostRouteTable = func() error { return nil }
		restoreHostDNS = func() error { return nil }
	}
	lockHost = func() (func(), error) { return func() {}, nil }
	os.Exit(m.Run())
}
