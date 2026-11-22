package lab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// nodePool is the node phase's pool of GoTestTopology labs (GoTestEach):
// its packages take turns in them, each lab reset and checked between two
// packages (Pool).
type nodePool struct {
	*Pool
	project func(i int) string // the Compose project of the pool's i-th lab
	seq     atomic.Int64       // labs it began to start
}

// newNodePool is a pool of up to size labs for packages packages, each of
// which goes through goTest or skip once.
func newNodePool(size, packages int, project func(i int) string) *nodePool {
	p := &nodePool{Pool: newPool(GoTestTopology(), size), project: project}
	p.countTakers(packages)
	return p
}

// nodePoolProject is the Compose project of GoTestEach's i-th pooled lab.
func nodePoolProject(checkout, run string, i int) string {
	return ownGoTestPackageProject(checkout, run, fmt.Sprintf("node pool lab %d", i))
}

// packagePool is where GoTestEach runs a package that has no FreshLabFile:
// a nodePool, or a unit test's stand-in.
type packagePool interface {
	goTest(ctx context.Context, queued time.Time, root, user string, w io.Writer, verbose bool, run func(n *Node) labRun) labRun
	// skip: the package won't take a lab (served from the cache, no
	// tests to run, or it never got past the gates).
	skip()
}

// goTest runs run in the node of one of the pool's labs, an idle one or
// one it starts, then gives the lab back: reset for the next package, or
// retired when the package failed (run's testErr) or the reset didn't
// hold. user names the package in the pool's log lines (what the reset
// undid), which go to w when verbose or when the reset didn't hold, and
// w gets which lab it ran in. The phases are timed from queued
// (LabPhases).
func (p *nodePool) goTest(ctx context.Context, queued time.Time, root, user string, w io.Writer, verbose bool, run func(n *Node) labRun) (res labRun) {
	timer := labTimer{queued: queued, began: time.Now()}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(labBudget.wait)
	}
	// The start may go on after the package took a lab that came back
	// meanwhile (startOrTake), so its slot wait is the package's only
	// when it is done by then.
	var slotWait atomic.Int64
	pl, err := p.acquire(ctx, deadline, unranked, func(ctx context.Context) (*pooledLab, error) {
		begin := time.Now()
		var st labTimer
		l, err := up(ctx, st.startClock(), root, p.project(int(p.seq.Add(1))), GoTestTopology(), "", runInputs)
		slotWait.Store(int64(st.slotWait))
		return p.adopt(l, nodeLab{l}, begin, err)
	})
	timer.started = time.Now()
	timer.slotWait = time.Duration(slotWait.Load())
	if err != nil {
		res.labErr = err
		res.phases = timer.phases(time.Now())
		return res
	}
	_, _ = fmt.Fprintf(w, "lab %s (pool %s, use %d)\n", pl.lab.Project, p.name, pl.uses)
	res = run(pl.lab.Node("gotest"))
	timer.tested = time.Now()
	u := &packageUser{name: user, failed: res.testErr != nil}
	if back := p.giveBack(u, pl, timer.started); verbose || !back && !u.failed {
		_, _ = w.Write(u.log.Bytes())
	}
	res.labErr = errors.Join(u.errs...)
	res.phases = timer.phases(time.Now())
	return res
}

// nodeLab is a lab of the node phase's pool. Like a fresh node-phase lab,
// a failed package's lab is torn down, never kept.
type nodeLab struct{ lab *Lab }

func (n nodeLab) name() string { return n.lab.Project }

func (n nodeLab) reset(ctx context.Context, clean *Snapshot, logf func(format string, args ...any)) error {
	return n.lab.Reset(ctx, clean, logf)
}

func (n nodeLab) cleanup(u labUser, _ time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
	defer cancel()
	if err := n.lab.Down(ctx); err != nil {
		u.Errorf("lab %s: tear down: %v", n.lab.Project, err)
	}
}

func (n nodeLab) keep(labUser) bool { return false }

func (n nodeLab) down(ctx context.Context) error { return n.lab.Down(ctx) }

// packageUser is a node-phase package as the user of a pool's lab: the
// pool's log lines go to log, and an error (a tear-down that failed) is
// the run's lab error.
type packageUser struct {
	name   string
	failed bool
	mu     sync.Mutex
	log    bytes.Buffer
	errs   []error
}

func (u *packageUser) Name() string { return u.name }
func (u *packageUser) Failed() bool { return u.failed }

func (u *packageUser) Logf(format string, args ...any) {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, _ = fmt.Fprintf(&u.log, format+"\n", args...)
}

func (u *packageUser) Errorf(format string, args ...any) {
	err := fmt.Errorf(format, args...)
	u.mu.Lock()
	u.errs = append(u.errs, err)
	u.mu.Unlock()
	u.Logf("%v", err)
}
