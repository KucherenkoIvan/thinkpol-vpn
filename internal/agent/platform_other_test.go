//go:build !linux || android

package agent

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// On a host without a data plane, a node with a valid state refuses to run
// before it creates or configures anything.
func TestRunRefusesAnUnsupportedHost(t *testing.T) {
	s := newTestSpace(t)
	var out bytes.Buffer
	logs, err := NewLogs("info", &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []NodeKeys{s.a, s.b} {
		n, err := Prepare(testConfig(s.stateDir(t, k, 1)), logs)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Run(context.Background(), nil); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s mode: got %v, want ErrUnsupported", n.Mode(), err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("it started: %s", out.String())
	}
}
