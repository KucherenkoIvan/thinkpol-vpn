//go:build linux && !android

package supervisor

import (
	"os"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// TestSetSpacesRollsBackOnIsolationFailure checks that when the isolation-table
// rebuild fails, SetSpaces unregisters the workers it had started (none has a
// goroutine yet), frees their slots and cgroups, and a later Close does not
// hang waiting on them. White-box: it injects the failure.
func TestSetSpacesRollsBackOnIsolationFailure(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	failApplyIsolation = true
	defer func() { failApplyIsolation = false }()
	s, err := New(Options{Command: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("New (install must not fail, only the rebuild): %v", err)
	}
	if err := s.SetSpaces([]Space{{ID: netmap.NewSpaceID()}}); err == nil {
		t.Fatal("SetSpaces returned nil despite the injected isolation failure")
	}
	if ws := s.Workers(); len(ws) != 0 {
		t.Fatalf("workers after a failed SetSpaces: %+v, want none", ws)
	}
	s.mu.Lock()
	leftSlots := len(s.slots)
	s.mu.Unlock()
	if leftSlots != 0 {
		t.Fatalf("%d slots left after rollback, want 0", leftSlots)
	}
	// Close must not hang on a worker that was registered but never supervised.
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Close hung after a rolled-back SetSpaces")
	}
}
