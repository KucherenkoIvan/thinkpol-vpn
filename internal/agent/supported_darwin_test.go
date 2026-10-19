package agent

import (
	"bytes"
	"errors"
	"testing"
)

// On macOS a device runs; a server refuses before it creates or
// configures anything. Adapters only builds what runs the node: nothing is
// started here.
func TestOnlyADeviceRunsOnMacOS(t *testing.T) {
	s := newTestSpace(t)
	var out bytes.Buffer
	logs, err := NewLogs("info", &out)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[Mode]bool{}
	for _, k := range []NodeKeys{s.a, s.b} {
		n, err := Prepare(testConfig(s.stateDir(t, k, 1)), logs, testPlatform())
		if err != nil {
			t.Fatal(err)
		}
		seen[n.Mode()] = true
		_, err = n.Adapters(nil)
		if n.Mode() == ModeServer && !errors.Is(err, ErrUnsupported) {
			t.Errorf("server: %v, want ErrUnsupported", err)
		}
		if n.Mode() == ModeDevice && err != nil {
			t.Errorf("device: %v", err)
		}
	}
	if !seen[ModeServer] || !seen[ModeDevice] {
		t.Fatalf("modes tried: %v", seen)
	}
	if out.Len() != 0 {
		t.Fatalf("it started: %s", out.String())
	}
}
