//go:build linux && !android

package worker_test

import (
	"context"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// The sandbox mounts over /proc, /sys and /run, so a worker started
// anywhere but in the supervisor's fresh namespaces refuses before touching
// anything. Workers themselves are tested through the supervisor.
func TestRefusesOutsideItsNamespaces(t *testing.T) {
	err := worker.Run(context.Background(), netmap.NewSpaceID(), worker.Idle)
	if err == nil || !strings.Contains(err.Error(), "not started by a supervisor") {
		t.Fatalf("Run outside a supervisor: %v", err)
	}
}
