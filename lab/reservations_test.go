package lab

import (
	"bufio"
	"context"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDaemon is the networks Docker has: a lab's subnets appear on it only
// once its docker compose up has created them, a while after they were
// reserved.
type fakeDaemon struct {
	mu   sync.Mutex
	nets []netip.Prefix
}

func (d *fakeDaemon) used(context.Context) ([]netip.Prefix, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.Prefix(nil), d.nets...), nil
}

func (d *fakeDaemon) create(s map[string]netSubnets) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, n := range s {
		d.nets = append(d.nets, n.v4)
	}
}

// Many labs reserving at once, each starting its networks only after the
// allocation lock is free again, never get a subnet twice: the
// reservations, not the daemon, keep them apart until the networks exist.
func TestConcurrentReservationsNeverShareASubnet(t *testing.T) {
	const labs = 30
	dir := t.TempDir()
	pool := netip.MustParsePrefix("172.16.0.0/18") // 64 /24s for 60 networks
	nets := []Network{{Name: "a", IPv4Only: true}, {Name: "b", IPv4Only: true}}
	daemon := &fakeDaemon{}
	var (
		mu  sync.Mutex
		got = map[netip.Prefix]string{}
		wg  sync.WaitGroup
	)
	for i := range labs {
		wg.Go(func() {
			r, err := reserveSubnets(t.Context(), dir, nets, pool, daemon.used)
			if err != nil {
				t.Errorf("lab %d: %v", i, err)
				return
			}
			mu.Lock()
			for name, s := range r.subnets {
				if other, dup := got[s.v4]; dup {
					t.Errorf("lab %d network %s got %v, already lab %s's", i, name, s.v4, other)
				}
				got[s.v4] = fmt.Sprintf("%d/%s", i, name)
			}
			mu.Unlock()
			// docker compose up, outside the lock.
			time.Sleep(time.Duration(mrand.IntN(20)) * time.Millisecond)
			daemon.create(r.subnets)
			r.release()
		})
	}
	wg.Wait()
	if len(got) != labs*len(nets) {
		t.Errorf("%d distinct subnets, want %d", len(got), labs*len(nets))
	}
	if left := reservationFiles(t, dir); len(left) > 0 {
		t.Errorf("released reservations left behind: %v", left)
	}
}

// A reservation outlives the allocation lock: another process sees it and
// stays off its subnet until the owner dies. Then the subnet is reclaimed,
// by the next allocation or by labctl down's sweep.
func TestReservationOfADeadOwnerIsReclaimed(t *testing.T) {
	pool := netip.MustParsePrefix("172.16.9.0/24") // a single /24
	nets := []Network{{Name: "a", IPv4Only: true}}
	none := func(context.Context) ([]netip.Prefix, error) { return nil, nil }
	for name, reclaim := range map[string]func(t *testing.T, dir string){
		"by the next allocation": func(*testing.T, string) {},
		"by labctl down": func(t *testing.T, dir string) {
			if err := reclaimReservations(t.Context(), dir); err != nil {
				t.Fatal(err)
			}
			if left := reservationFiles(t, dir); len(left) > 0 {
				t.Errorf("a dead owner's reservation survived the sweep: %v", left)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			owner := startReservingProcess(t, dir, pool)
			if r, err := reserveSubnets(t.Context(), dir, nets, pool, none); err == nil {
				r.release()
				t.Fatalf("got %v, which a live process holds", r.subnets["a"].v4)
			}
			if err := owner.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = owner.Wait()
			reclaim(t, dir)
			r, err := reserveSubnets(t.Context(), dir, nets, pool, none)
			if err != nil {
				t.Fatalf("the dead owner's subnet wasn't reclaimed: %v", err)
			}
			defer r.release()
			if r.subnets["a"].v4 != pool {
				t.Errorf("got %v, want %v", r.subnets["a"].v4, pool)
			}
		})
	}
}

const reservingProcessEnv = "THINKPOL_LAB_TEST_RESERVE_DIR"

// startReservingProcess runs TestReservingProcess in a child, which
// reserves pool in dir and holds it until killed.
func startReservingProcess(t *testing.T, dir string, pool netip.Prefix) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestReservingProcess$", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), reservingProcessEnv+"="+dir, SubnetPoolEnv+"="+pool.String())
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	lines := bufio.NewScanner(out)
	for lines.Scan() {
		if line := lines.Text(); strings.HasPrefix(line, "reserved ") {
			if line != "reserved "+pool.String() {
				t.Fatalf("child: %s", line)
			}
			return cmd
		}
	}
	t.Fatalf("the child exited without reserving: %v", lines.Err())
	return nil
}

func TestReservingProcess(t *testing.T) {
	dir := os.Getenv(reservingProcessEnv)
	if dir == "" {
		t.Skip("the child of TestReservationOfADeadOwnerIsReclaimed")
	}
	pool, err := subnetPool()
	if err != nil {
		t.Fatal(err)
	}
	r, err := reserveSubnets(t.Context(), dir, []Network{{Name: "a", IPv4Only: true}}, pool, func(context.Context) ([]netip.Prefix, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("reserved", r.subnets["a"].v4)
	time.Sleep(time.Hour)
}

func reservationFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(reservationsDir(dir), "*"+reservationSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return files
}
