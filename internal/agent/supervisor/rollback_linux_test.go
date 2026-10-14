//go:build linux && !android

package supervisor

import (
	"os"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/egress"
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

// TestSetSpacesRetriesEgressAfterIsolationFailure checks that when
// applyIsolation fails for an existing space, the worker's egress is put back
// and a later SetSpaces with the same grant still turns forwarding on.
func TestSetSpacesRetriesEgressAfterIsolationFailure(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	const forward4 = "net/ipv4/ip_forward"
	was, err := os.ReadFile("/proc/sys/" + forward4)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/"+forward4, []byte("0"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile("/proc/sys/"+forward4, was, 0) })

	space := netmap.NewSpaceID()
	s, err := New(Options{
		Command:    []string{"/bin/true"},
		RuntimeDir: t.TempDir(),
		Uplink: func() (egress.Uplink, error) {
			return egress.Uplink{Name: "lo", IPv4: true}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.SetSpaces([]Space{{ID: space}}); err != nil {
		t.Fatalf("first SetSpaces: %v", err)
	}

	grant := EgressGrant{IPv4: true}
	t.Cleanup(func() { failApplyIsolation = false })
	failApplyIsolation = true
	if err := s.SetSpaces([]Space{{ID: space, Egress: grant}}); err == nil {
		failApplyIsolation = false
		t.Fatal("SetSpaces returned nil despite the injected isolation failure")
	}
	failApplyIsolation = false
	s.mu.Lock()
	eg, _ := s.workers[space].egressRules()
	s.mu.Unlock()
	if eg.IPv4 {
		t.Fatal("egress left updated in memory after a failed table rebuild")
	}

	if err := s.SetSpaces([]Space{{ID: space, Egress: grant}}); err != nil {
		t.Fatalf("retry SetSpaces: %v", err)
	}
	fwd, err := readSysctl(forward4)
	if err != nil {
		t.Fatal(err)
	}
	if fwd != "1" {
		t.Fatalf("forwarding not turned on after retry: %s", fwd)
	}
}

// TestCloseTeardownOrder checks that Close turns root forwarding off before
// it removes the isolation tables.
func TestCloseTeardownOrder(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	var order []string
	testCloseTeardown = func(step string) { order = append(order, step) }
	defer func() { testCloseTeardown = nil }()

	s, err := New(Options{Command: []string{"/bin/true"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SetSpaces([]Space{{ID: netmap.NewSpaceID(), Egress: EgressGrant{IPv4: true}}}); err != nil {
		t.Fatalf("SetSpaces: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if order == nil {
		t.Fatal("testCloseTeardown was not called")
	}
	if len(order) < 2 || order[0] != "forwarding" || order[1] != "isolation" {
		t.Fatalf("Close teardown order %v, want forwarding then isolation", order)
	}
}
