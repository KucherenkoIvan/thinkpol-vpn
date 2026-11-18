//go:build lab

package lab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A network removed by someone else between the list and the inspect
// doesn't fail allocation: two throwaway networks of the test's own, one of
// them removed right after `docker network ls`.
func TestHarnessUsedSubnetsSurvivesANetworkRemovedMidway(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	subnetOf, idOf := map[string]netip.Prefix{}, map[string]string{}
	for _, role := range []string{"gone", "kept"} {
		name := ProjectPrefix + "subnet-race-" + role + "-" + hex.EncodeToString(suffix)
		t.Cleanup(func() { _, _ = docker(context.Background(), "network", "rm", name) })
		res, err := docker(ctx, "network", "create", name)
		if err != nil {
			t.Fatal(err)
		}
		idOf[role] = strings.TrimSpace(res.Stdout)
		res, err = docker(ctx, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}", name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(res.Stdout))
		if err != nil {
			t.Fatalf("%s: subnet %q: %v", name, res.Stdout, err)
		}
		subnetOf[role] = p.Masked()
	}
	removed := false
	racing := func(ctx context.Context, args ...string) (Result, error) {
		res, err := docker(ctx, args...)
		if err == nil && !removed && slices.Equal(args, []string{"network", "ls", "-q", "--no-trunc"}) {
			if !slices.Contains(strings.Fields(res.Stdout), idOf["gone"]) {
				t.Fatal("the throwaway network isn't listed")
			}
			if _, err := docker(ctx, "network", "rm", idOf["gone"]); err != nil {
				t.Fatal(err)
			}
			removed = true
		}
		return res, err
	}
	used, err := usedSubnetsVia(ctx, racing)
	if err != nil {
		t.Fatalf("a network removed mid-allocation failed it: %v", err)
	}
	if !removed {
		t.Fatal("the network was never removed")
	}
	if !slices.Contains(used, subnetOf["kept"]) {
		t.Errorf("the kept network's %v is missing from %v", subnetOf["kept"], used)
	}
	if slices.Contains(used, subnetOf["gone"]) {
		t.Errorf("the removed network's %v still counts as used", subnetOf["gone"])
	}
}

// Labs starting at once run their docker compose up side by side, not one
// after another under the subnet allocation lock, and still get subnets of
// their own: four labs of one test (one lab slot), all up together.
func TestHarnessLabStartsOverlapOnDistinctSubnets(t *testing.T) {
	t.Parallel()
	const labs = 4
	// The labs' subtests wait on each other, each holding a -parallel slot:
	// with fewer slots than labs they'd wait until the run's timeout.
	if p := flag.Lookup("test.parallel"); p != nil {
		if n, ok := p.Value.(flag.Getter).Get().(int); ok && n < labs {
			t.Skipf("needs -parallel %d or more to start %d labs at once, got %d", labs, labs, n)
		}
	}
	topo := Topology{
		Networks: []Network{{Name: "a"}, {Name: "b", IPv4Only: true}},
		Nodes:    []NodeSpec{{Name: "n", Networks: []string{"a", "b"}}},
	}
	type started struct {
		project  string
		from, to time.Time
		attempt  int
		subnets  []netip.Prefix
	}
	var (
		mu    sync.Mutex
		all   []started
		allUp sync.WaitGroup
	)
	allUp.Add(labs)
	t.Run("labs", func(t *testing.T) {
		for i := range labs {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()
				var once sync.Once
				up := func() { once.Do(allUp.Done) }
				defer up()
				l := Start(t, topo)
				s := started{project: l.Project, from: l.upFrom, to: l.upTo, attempt: l.upAttempt}
				for _, n := range topo.Networks {
					res, err := docker(t.Context(), "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", l.Project+"_"+n.Name)
					if err != nil {
						t.Fatal(err)
					}
					for _, f := range strings.Fields(res.Stdout) {
						p, err := netip.ParsePrefix(f)
						if err != nil {
							t.Fatalf("%s: subnet %q: %v", n.Name, f, err)
						}
						s.subnets = append(s.subnets, p.Masked())
					}
				}
				mu.Lock()
				all = append(all, s)
				mu.Unlock()
				// Every lab stays up until all have read their subnets.
				up()
				allUp.Wait()
			})
		}
	})
	if t.Failed() {
		return
	}
	owner := map[netip.Prefix]string{}
	for _, s := range all {
		t.Logf("%s: docker compose up %s-%s, attempt %d, subnets %v", s.project, s.from.Format("15:04:05.000"), s.to.Format("15:04:05.000"), s.attempt, s.subnets)
		// Docker refuses an overlapping network and the loser retries, so
		// distinct subnets alone don't show the reservations kept them apart.
		if s.attempt != 1 {
			t.Errorf("%s came up on attempt %d: Docker refused an overlapping subnet the reservations let through", s.project, s.attempt)
		}
		for _, p := range s.subnets {
			for q, other := range owner {
				if p.Overlaps(q) {
					t.Errorf("%s's %v overlaps %s's %v, both up at once", s.project, p, other, q)
				}
			}
			owner[p] = s.project
		}
	}
	overlapping := 0
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.from.Before(b.to) && b.from.Before(a.to) {
				overlapping++
			}
		}
	}
	if overlapping == 0 {
		t.Errorf("no two of %d labs started at once ran docker compose up at the same time: their start-ups were serialized", labs)
	}
}
