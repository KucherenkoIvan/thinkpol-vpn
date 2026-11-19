package lab

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// idleNodePool is a node pool of size labs, all started and idle (fakes),
// for packages packages.
func idleNodePool(t *testing.T, packages int, labs ...*fakeLab) *nodePool {
	t.Helper()
	p := newNodePool(len(labs), packages, func(int) string {
		t.Fatal("a lab start: the pool has idle labs")
		return ""
	})
	for _, f := range labs {
		p.idle = append(p.idle, &pooledLab{
			lab:   &Lab{Project: f.project, nodes: map[string]*Node{"gotest": {Name: "gotest"}}},
			ops:   f,
			timer: time.NewTimer(time.Hour),
		})
	}
	p.labs = len(labs)
	return p
}

// TestNodePoolOutput: a package's output says which lab it ran in; what
// the reset undid goes to it only with -v, while why a reset didn't hold
// goes to it either way.
func TestNodePoolOutput(t *testing.T) {
	t.Setenv(TimelineEnv, "") // its labs aren't the run's
	for _, c := range []struct {
		what     string
		verbose  bool
		resetErr error
		want     []string
		notWant  []string
	}{
		{"a reset that held, not verbose", false, nil, []string{"lab lab-1 (pool gotest, use 1)\n"}, []string{"undid"}},
		{"a reset that held, verbose", true, nil, []string{"lab lab-1 (pool gotest, use 1)\n", "the reset undid what was left behind:\n  process 90 sleep 1000"}, nil},
		{"a reset that didn't hold, not verbose", false, errors.New("gotest: left behind: file /var/lib/x"), []string{"didn't hold", "/var/lib/x"}, nil},
	} {
		f := &fakeLab{project: "lab-1", undone: "\n  process 90 sleep 1000", resetErr: c.resetErr}
		p := idleNodePool(t, 2, f)
		var w bytes.Buffer
		res := p.goTest(t.Context(), time.Now(), "", "example.net/x", &w, c.verbose, func(*Node) labRun { return labRun{} })
		if res.labErr != nil || res.testErr != nil {
			t.Errorf("%s: lab %v, tests %v", c.what, res.labErr, res.testErr)
		}
		for _, s := range c.want {
			if !strings.Contains(w.String(), s) {
				t.Errorf("%s: output without %q:\n%s", c.what, s, w.String())
			}
		}
		for _, s := range c.notWant {
			if strings.Contains(w.String(), s) {
				t.Errorf("%s: output with %q:\n%s", c.what, s, w.String())
			}
		}
		if err := p.close(io.Discard, "packages"); err != nil {
			t.Errorf("%s: close: %v", c.what, err)
		}
	}
}

// TestNodePoolTearsDownWhatNoPackageTakes: the pool keeps no more labs
// idle than packages may still take one, tearing the longest idle down
// first, and none once no package is left; a tear-down that failed is the
// pool's error when it closes.
func TestNodePoolTearsDownWhatNoPackageTakes(t *testing.T) {
	t.Setenv(TimelineEnv, "") // its labs aren't the run's
	a := &fakeLab{project: "lab-a", downErr: errors.New("compose down: exit 1")}
	b := &fakeLab{project: "lab-b"}
	p := idleNodePool(t, 3, a, b)
	downs := func() (int, int, int) {
		p.down.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		return a.counts()[3], b.counts()[3], len(p.idle)
	}

	p.skip() // served from the cache
	if da, db, idle := downs(); da+db != 0 || idle != 2 {
		t.Fatalf("two packages left for two idle labs: downs %d, %d, %d idle: want both kept", da, db, idle)
	}
	var ran string
	res := p.goTest(t.Context(), time.Now(), "", "example.net/x", io.Discard, false, func(n *Node) labRun {
		ran = n.Name
		if da, db, idle := downs(); da+db != 0 || idle != 1 {
			t.Errorf("one package left, one lab idle: downs %d, %d, %d idle: want it kept", da, db, idle)
		}
		return labRun{}
	})
	if res.labErr != nil || ran != "gotest" {
		t.Fatalf("the package ran in %q: %v", ran, res.labErr)
	}
	if da, db, idle := downs(); da != 1 || db != 0 || idle != 1 {
		t.Errorf("its lab given back, one package left: downs %d, %d, %d idle: want the longest idle torn down", da, db, idle)
	}
	p.skip()
	if da, db, idle := downs(); da != 1 || db != 1 || idle != 0 || p.labs != 0 {
		t.Errorf("no package left: downs %d, %d, %d idle, %d labs: want none kept", da, db, idle, p.labs)
	}
	var stats strings.Builder
	if err := p.close(&stats, "packages"); err == nil || !strings.Contains(err.Error(), "lab lab-a: tear down: compose down: exit 1") {
		t.Errorf("close: %v, want lab-a's tear-down", err)
	}
	if want := "lab pool gotest: 0 labs started for 1 packages, 0 retired\n"; stats.String() != want {
		t.Errorf("stats %q, want %q", stats.String(), want)
	}
}

// fakePackagePool counts the packages that went to the pool.
type fakePackagePool struct{ goTests, skips int }

func (f *fakePackagePool) goTest(_ context.Context, _ time.Time, _, _ string, _ io.Writer, _ bool, _ func(n *Node) labRun) labRun {
	f.goTests++
	return labRun{}
}

func (f *fakePackagePool) skip() { f.skips++ }

// TestFreshLabPackageSkipsThePool: a package with FreshLabFile runs in a
// lab of its own and never reaches the pool; one without goes to the pool.
func TestFreshLabPackageSkipsThePool(t *testing.T) {
	for _, freshLab := range []bool{true, false} {
		pool := &fakePackagePool{}
		fresh := 0
		r := &packageRun{
			ctx:  t.Context(),
			pkg:  GoPackage{ImportPath: "example.net/x", FreshLab: freshLab},
			out:  &bytes.Buffer{},
			pool: pool,
			fresh: func(context.Context, time.Time, string, string, GoPackage, io.Writer, []string, []string, bool) labRun {
				fresh++
				return labRun{}
			},
		}
		r.inLab(time.Now())
		want := [2]int{0, 1}
		if freshLab {
			want = [2]int{1, 0}
		}
		if got := [2]int{fresh, pool.goTests}; got != want || pool.skips != 0 {
			t.Errorf("FreshLab %v: fresh labs, pool runs %v, want %v; %d skips", freshLab, got, want, pool.skips)
		}
	}
}
