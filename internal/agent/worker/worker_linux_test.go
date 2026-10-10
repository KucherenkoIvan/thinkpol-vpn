//go:build linux && !android

package worker_test

import (
	"context"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/worker"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Run needs the supervisor's sockets at ipc.ControlFD and ipc.DataFD; started
// by hand (no such sockets) it fails before touching anything. Workers
// themselves are tested through the supervisor, which sets up the namespaces.
func TestRefusesWithoutItsSockets(t *testing.T) {
	err := worker.Run(context.Background(), netmap.NewSpaceID(), worker.Idle)
	if err == nil || !strings.Contains(err.Error(), "socket") {
		t.Fatalf("Run without the supervisor's sockets: %v", err)
	}
}
