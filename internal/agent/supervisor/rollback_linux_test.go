//go:build linux && !android

package supervisor

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/egress"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// errInjected is the failure the tests inject into a table rebuild.
var errInjected = errors.New("injected table rebuild failure")

// failRebuilds makes every rebuild with slots fail with errInjected (after
// before, if set) until the test ends or it is called again. The failure is
// injected through the supervisor's rebuild failer (Options.failIsolation,
// set at New), which the rebuild asks before it touches nftables; the test
// arms and disarms it, never writing the supervisor's options.
func failRebuilds(t *testing.T, s *Supervisor, before func()) {
	t.Helper()
	if s.opts.failIsolation == nil {
		t.Fatal("the supervisor has no rebuild failer to arm")
	}
	s.opts.failIsolation.arm(before)
	t.Cleanup(s.opts.failIsolation.disarm)
}

// realSysctl reads one of the root namespace's real sysctls, for the tests
// that watch the real thing.
func realSysctl(key string) (string, error) {
	return procSysFS{root: "/proc/sys"}.Read(key)
}

// TestSetSpacesRollsBackOnIsolationFailure checks that when the isolation-table
// rebuild fails, SetSpaces unregisters the workers it had started (none has a
// goroutine yet), frees their slots and cgroups, and a later Close does not
// hang waiting on them. White-box: it injects the failure.
func TestSetSpacesRollsBackOnIsolationFailure(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	s, err := New(Options{Command: []string{"/bin/true"}, failIsolation: &rebuildFailer{err: errInjected}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	failRebuilds(t, s, nil)
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

// egressAccept is in a space's namespace table (nft's listing) exactly when
// it forwards the space's IPv4 egress.
const egressAccept = "meta nfproto ipv4 accept"

// probeOptions run the test binary's probe worker (TestMain in
// supervisor_linux_test.go), which reports each config it gets, with "lo" as
// the uplink: nothing is sent, only the tables are looked at.
func probeOptions(t *testing.T) Options {
	return Options{
		Env:           []string{"SUPERVISOR_TEST_WORKER=1", "SUPERVISOR_TEST_PROBE=1"},
		Backoff:       Backoff{Initial: 50 * time.Millisecond, Max: 400 * time.Millisecond, ResetAfter: 10 * time.Second},
		ReadyTimeout:  15 * time.Second,
		StopTimeout:   3 * time.Second,
		PidsMax:       512,
		MemoryMax:     256 << 20,
		RuntimeDir:    t.TempDir(),
		Uplink:        func() (egress.Uplink, error) { return egress.Uplink{Name: "lo", IPv4: true}, nil },
		failIsolation: &rebuildFailer{err: errInjected},
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := cond()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// readyPID waits for space's worker to be ready with a pid other than not,
// and returns it.
func readyPID(t *testing.T, s *Supervisor, space netmap.SpaceID, not int) int {
	t.Helper()
	var pid int
	waitFor(t, 25*time.Second, "the worker ready", func() error {
		for _, w := range s.Workers() {
			if w.Space == space && w.Ready && w.PID != 0 && w.PID != not {
				pid = w.PID
				return nil
			}
		}
		return fmt.Errorf("not yet: %q", s.Output(space))
	})
	return pid
}

// spaceTableOf is the worker pid's namespace table, as nft lists it.
func spaceTableOf(pid int) (string, error) {
	out, err := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid), "nft", "list", "table", "inet", SpaceTableName).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("the space's table: %v: %s", err, out)
	}
	return string(out), nil
}

// awaitSpaceTable waits until pid's namespace table forwards IPv4 egress, or
// doesn't (forwards).
func awaitSpaceTable(t *testing.T, pid int, forwards bool, timeout time.Duration) {
	t.Helper()
	waitFor(t, timeout, fmt.Sprintf("the space's table forwarding egress: %v", forwards), func() error {
		table, err := spaceTableOf(pid)
		if err != nil {
			return err
		}
		if strings.Contains(table, egressAccept) != forwards {
			return fmt.Errorf("it doesn't:\n%s", table)
		}
		return nil
	})
}

// configsGot are the sha256 of each config the probe worker reported
// getting, in order.
func configsGot(s *Supervisor, space netmap.SpaceID) []string {
	var out []string
	for _, l := range s.Output(space) {
		if rest, ok := strings.CutPrefix(l, "probe config sha256="); ok {
			out = append(out, strings.Fields(rest)[0])
		}
	}
	return out
}

func sum(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// A table rebuild that fails for a running space leaves its egress to be
// applied by the next SetSpaces that asks for it again: the space's own
// namespace table follows then. The config pushed with the failed SetSpaces
// stays the worker's: it isn't taken back (which would make it drop the
// seeds only the new map names, never sent again), and nor are the space's
// inbound credentials at the shared listeners.
func TestEgressAppliedAfterAFailedTableRebuild(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	s, err := New(probeOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	space := netmap.NewSpaceID()
	first, second := []byte("first config"), []byte("second config")
	if err := s.SetSpaces([]Space{{ID: space, Config: first}}); err != nil {
		t.Fatal(err)
	}
	pid := readyPID(t, s, space, 0)
	waitFor(t, 10*time.Second, "the first config", func() error {
		if got := configsGot(s, space); len(got) != 1 || got[0] != sum(first) {
			return fmt.Errorf("got %q", got)
		}
		return nil
	})
	awaitSpaceTable(t, pid, false, time.Second)

	want := []Space{{
		ID: space, Config: second, Egress: EgressGrant{IPv4: true},
		Inbound: map[string][]transport.PeerLink{"udp": nil},
	}}
	failRebuilds(t, s, nil)
	if err := s.SetSpaces(want); !errors.Is(err, errInjected) {
		t.Fatalf("SetSpaces with the rebuild failing: %v", err)
	}
	s.opts.failIsolation.disarm()
	firstThenSecond := func() error {
		if got := configsGot(s, space); len(got) != 2 || got[0] != sum(first) || got[1] != sum(second) {
			return fmt.Errorf("configs the worker got %q, want the first then the second, once each", got)
		}
		return nil
	}
	waitFor(t, 10*time.Second, "the second config", firstThenSecond)
	if err := s.SetSpaces(want); err != nil {
		t.Fatalf("SetSpaces again: %v", err)
	}
	awaitSpaceTable(t, pid, true, 10*time.Second)

	time.Sleep(time.Second) // for anything still on its way to the worker
	if err := firstThenSecond(); err != nil {
		t.Error(err)
	}
	s.mu.Lock()
	inbound := s.workers[space].inbound
	s.mu.Unlock()
	if _, ok := inbound["udp"]; !ok {
		t.Errorf("the space's inbound credentials were taken back: %v", inbound)
	}
	if got := readyPID(t, s, space, 0); got != pid {
		t.Fatalf("the worker restarted (pid %d, was %d): the table was rewritten by wire, not by the retry", got, pid)
	}
}

// A worker restarting while a SetSpaces's rebuild is underway wires its new
// namespace for the egress being asked for; when the rebuild fails, that
// table is put back in step with the root's, which never had the egress.
func TestRestartDuringAFailedRebuildKeepsTheSpaceTableInStep(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	s, err := New(probeOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	space := netmap.NewSpaceID()
	if err := s.SetSpaces([]Space{{ID: space}}); err != nil {
		t.Fatal(err)
	}
	pid := readyPID(t, s, space, 0)

	var restarted int
	failRebuilds(t, s, func() {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Errorf("killing the worker: %v", err)
			return
		}
		restarted = readyPID(t, s, space, pid)
		// The window this test is about: the new namespace forwards the
		// egress the root's tables are about not to.
		awaitSpaceTable(t, restarted, true, time.Second)
	})
	if err := s.SetSpaces([]Space{{ID: space, Egress: EgressGrant{IPv4: true}}}); !errors.Is(err, errInjected) {
		t.Fatalf("SetSpaces with the rebuild failing: %v", err)
	}
	if restarted == 0 {
		t.FailNow()
	}
	awaitSpaceTable(t, restarted, false, 10*time.Second)
}

// hasRootTables reports whether the supervisor's isolation table is in the
// root namespace.
func hasRootTables(t *testing.T) bool {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tables {
		if tb.Name == TableName {
			return true
		}
	}
	return false
}

// forwardingOff turns the root's IPv4 forwarding off for the test, so the
// supervisor turns it on (and owns it), and puts it back after.
func forwardingOff(t *testing.T) {
	t.Helper()
	const key = "/proc/sys/net/ipv4/ip_forward"
	was, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("0"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(key, was, 0) })
}

// servingWithEgress is a supervisor that turned the root's IPv4 forwarding
// on for a space's egress.
func servingWithEgress(t *testing.T, opts Options) *Supervisor {
	t.Helper()
	opts.Command = []string{"/bin/true"}
	opts.Uplink = func() (egress.Uplink, error) { return egress.Uplink{Name: "lo", IPv4: true}, nil }
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSpaces([]Space{{ID: netmap.NewSpaceID(), Egress: EgressGrant{IPv4: true}}}); err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	if v, _ := realSysctl(forwardingKeys[0]); v != "1" {
		_ = s.Close()
		t.Fatalf("forwarding %s while serving a space's egress", v)
	}
	return s
}

// Close turns the forwarding it turned on off while the isolation tables
// still confine it, never the other way round.
func TestCloseTurnsForwardingOffWhileTheTablesStand(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	forwardingOff(t)
	sys := &hookSysctls{procSysFS: procSysFS{root: "/proc/sys"}}
	s := servingWithEgress(t, Options{RuntimeDir: t.TempDir(), sysctls: sys})
	turnedOff, tablesThen := false, false
	sys.arm(func(key, value string) error {
		if key == forwardingKeys[0] && value == "0" {
			turnedOff, tablesThen = true, hasRootTables(t)
		}
		return nil
	})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !turnedOff || !tablesThen {
		t.Fatalf("forwarding turned off: %v, with the isolation tables there: %v", turnedOff, tablesThen)
	}
	if v, _ := realSysctl(forwardingKeys[0]); v != "0" || hasRootTables(t) {
		t.Fatalf("after Close: forwarding %s, tables there: %v", v, hasRootTables(t))
	}
}

// Forwarding Close can't turn off stays confined by the isolation tables,
// and recorded: the next supervisor adopts it, and turns it off even when
// it fails to start itself.
func TestForwardingCloseCannotTurnOffStaysConfined(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	forwardingOff(t)
	run := t.TempDir()
	record := filepath.Join(run, forwardingFile)
	sys := &hookSysctls{procSysFS: procSysFS{root: "/proc/sys"}}
	t.Cleanup(func() { _ = removeIsolation() })

	leftOn := func(t *testing.T) {
		t.Helper()
		s := servingWithEgress(t, Options{RuntimeDir: run, sysctls: sys})
		sys.arm(func(key, value string) error {
			if key == forwardingKeys[0] && value == "0" {
				return errors.New("refused")
			}
			return nil
		})
		if err := s.Close(); err == nil {
			t.Fatal("Close returned nil with the forwarding still on")
		}
		sys.disarm()
		v, _ := realSysctl(forwardingKeys[0])
		_, recErr := os.Stat(record)
		if v != "1" || !hasRootTables(t) || recErr != nil {
			t.Fatalf("after a Close that couldn't turn forwarding off: forwarding %s, tables there: %v, record: %v", v, hasRootTables(t), recErr)
		}
	}
	turnedOff := func(t *testing.T) {
		t.Helper()
		v, _ := realSysctl(forwardingKeys[0])
		_, recErr := os.Stat(record)
		if v != "0" || !errors.Is(recErr, os.ErrNotExist) {
			t.Fatalf("forwarding %s, record: %v", v, recErr)
		}
	}

	t.Run("adopted by the next supervisor", func(t *testing.T) {
		leftOn(t)
		s, err := New(Options{Command: []string{"/bin/true"}, RuntimeDir: run})
		if err != nil {
			t.Fatal(err)
		}
		turnedOff(t)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if hasRootTables(t) {
			t.Fatal("tables left after Close")
		}
	})
	t.Run("turned off by a supervisor that fails to start", func(t *testing.T) {
		leftOn(t)
		f := &rebuildFailer{err: errInjected, failEmpty: true}
		f.arm(nil) // from New on: the no-slot install fails too
		if _, err := New(Options{
			Command:       []string{"/bin/true"},
			RuntimeDir:    run,
			failIsolation: f,
		}); !errors.Is(err, errInjected) {
			t.Fatalf("New with the tables failing: %v", err)
		}
		turnedOff(t)
		if hasRootTables(t) {
			t.Fatal("tables left after a failed start that turned forwarding off")
		}
	})
}
