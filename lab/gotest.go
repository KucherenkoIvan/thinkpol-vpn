package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/testcache"
)

// GoPackage is a package whose tests GoTest can run in a lab node.
type GoPackage struct {
	ImportPath string
	Dir        string // relative to the checkout, slash-separated
	// NeedsNoNode: the package has HostTestsFile, so on a Linux machine
	// its tests run there (GoTestOnHost) rather than in a node.
	NeedsNoNode bool
	// FreshLab: the package has FreshLabFile, so GoTestEach runs it in a
	// lab of its own rather than one of its pool.
	FreshLab bool
}

// FreshLabFile marks a package whose tests change what a lab's reset
// doesn't read (lab/snapshot.go, nodeStateScript): a test file holding only
// the package clause and a comment saying what, so GoTestEach starts it a
// lab of its own instead of handing it one another package used.
const FreshLabFile = "freshlab_test.go"

// ListGoPackages expands go package patterns, as seen for linux, to the
// packages that have tests.
func ListGoPackages(ctx context.Context, root string, patterns ...string) ([]GoPackage, error) {
	args := append([]string{"-C", root, "list", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles"}, patterns...)
	res, err := run(ctx, nil, []string{"GOOS=linux", "CGO_ENABLED=0"}, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	var out []GoPackage
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	for dec.More() {
		var p struct {
			ImportPath                string
			Dir                       string
			TestGoFiles, XTestGoFiles []string
		}
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		if len(p.TestGoFiles)+len(p.XTestGoFiles) == 0 {
			continue
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return nil, err
		}
		files := slices.Concat(p.TestGoFiles, p.XTestGoFiles)
		out = append(out, GoPackage{ImportPath: p.ImportPath, Dir: filepath.ToSlash(rel), NeedsNoNode: slices.Contains(files, HostTestsFile), FreshLab: slices.Contains(files, FreshLabFile)})
	}
	return out, nil
}

// DefaultTestTimeout bounds a package's tests in a node unless the caller
// passes its own -test.timeout.
const DefaultTestTimeout = "10m"

// GoTest compiles a package's tests for linux and runs them in the node,
// as root, with THINKPOL_LAB=1 and the package's directory as the working
// directory, so tests that need root or network namespaces run instead of
// skipping. args go to the test binary (e.g. -test.run, -test.v). Output is
// streamed to w; the error is non-nil when the tests fail.
func (n *Node) GoTest(ctx context.Context, w io.Writer, pkg GoPackage, args ...string) error {
	return n.goTest(ctx, w, pkg, nil, args)
}

// goTest is GoTest with more environment (NAME=value) for the test binary.
func (n *Node) goTest(ctx context.Context, w io.Writer, pkg GoPackage, env, args []string) error {
	name, built, err := buildPackageTests(ctx, n.lab.root, n.lab.binDir, pkg)
	if err != nil || !built {
		return err // !built: no tests for linux
	}
	dockerArgs := []string{"exec", "-w", path.Join(SrcDir, pkg.Dir), "-e", "THINKPOL_LAB=1"}
	for _, e := range env {
		dockerArgs = append(dockerArgs, "-e", e)
	}
	dockerArgs = append(dockerArgs, n.Container, path.Join(BinDir, "tests", name))
	cmd := exec.CommandContext(ctx, "docker", append(dockerArgs, testBinaryArgs(args)...)...)
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: tests in %s: %w", n.Name, pkg.ImportPath, err)
	}
	return nil
}

// testBinaryArgs is what a test binary run as go test runs it gets: args,
// the default timeout unless args has one, and -test.paniconexit0, so a
// test calling os.Exit(0) fails the run instead of ending it green with the
// rest of the tests unrun.
func testBinaryArgs(args []string) []string {
	if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(strings.TrimLeft(a, "-"), "test.timeout") }) {
		args = append([]string{"-test.timeout=" + DefaultTestTimeout}, args...)
	}
	return append([]string{"-test.paniconexit0"}, args...)
}

// buildPackageTests builds a package's tests for the lab's platform into
// binDir's tests/, once per binary directory, and returns the binary's name
// there; built is false when the package has no tests for linux.
func buildPackageTests(ctx context.Context, root, binDir string, pkg GoPackage) (name string, built bool, err error) {
	t, err := dockerTarget(ctx)
	if err != nil {
		return "", false, err
	}
	name = testBinaryName(pkg)
	bin := filepath.Join(binDir, "tests", name)
	built, err = buildTestsOnce(bin, func() (bool, error) {
		// Without -trimpath the checkout's directory is compiled in, and
		// the binary's hash, part of the results cache's key, differs for
		// every checkout of the same commit.
		return goBuild(ctx, root, t, bin, "test", "-c", "-trimpath", "./"+pkg.Dir)
	})
	return name, built, err
}

// builtTests holds, by output path, this process's builds of packages'
// tests: each is built once per binary directory, never again under a lab
// running it.
var builtTests sync.Map // string → *testBuild

type testBuild struct {
	mu    sync.Mutex
	done  bool
	built bool // false: the package has no tests for linux
}

// buildTestsOnce runs build for the output bin until it succeeds once, and
// returns that build's result from then on. A failed build renamed nothing
// onto bin, so the next caller builds again.
func buildTestsOnce(bin string, build func() (bool, error)) (bool, error) {
	b, _ := builtTests.LoadOrStore(bin, &testBuild{})
	tb := b.(*testBuild)
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.done {
		return tb.built, nil
	}
	built, err := build()
	if err != nil {
		return false, err
	}
	tb.done, tb.built = true, built
	return built, nil
}

// testBinaryName is the file GoTest builds a package's tests into, under
// the lab's binary directory's tests/. The hash keeps a/b-c and a/b/c apart.
func testBinaryName(pkg GoPackage) string {
	return slug(path.Base(pkg.ImportPath), 40) + "-" + shortHash(pkg.ImportPath) + ".test"
}

// RunGoTests is GoTest for a lab test, in this node: the package's output
// goes to the test log and a failure fails the test.
func (n *Node) RunGoTests(t testing.TB, pkgPattern string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	pkgs, err := ListGoPackages(ctx, n.lab.root, pkgPattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		var out syncBuffer
		err := n.GoTest(ctx, &out, pkg, append([]string{"-test.v"}, args...)...)
		t.Logf("%s:\n%s", pkg.ImportPath, out.String())
		if err != nil {
			t.Error(err)
		}
	}
}

// GoTestResult is how one package's tests went in one run.
type GoTestResult struct {
	ImportPath string
	Failed     bool
	Cached     bool // not run: a recorded pass (GoTestCache)
	Tests      TestTally
	Elapsed    time.Duration // from its lab's start to its end: 0 when cached
	// Phases splits Elapsed for a package run in a lab node; zero for
	// one run on the host or not run.
	Phases LabPhases
}

// LabPhases is where a package's time in a lab node went: queued for one
// of the run's own labs (GoTestConcurrency.Labs; with BuildAllFirst, for
// every package's build too), waiting for a lab slot, starting the lab
// (the rest of its start-up: a leftover lab's removal, docker compose up,
// sealing the nodes, and for a pooled lab its snapshot; none for a lab
// another package used), running the tests (and reading their test log
// back), and tearing the lab down, or for a pooled lab that goes back,
// resetting it. A start that failed has no test time; its tear-down, if
// any, follows the start.
type LabPhases struct {
	Queue, SlotWait, Start, Tests, Teardown time.Duration
}

// IsZero says whether no phase was timed.
func (p LabPhases) IsZero() bool { return p == LabPhases{} }

// String is the phases for a report line, rounded to a tenth of a second.
func (p LabPhases) String() string {
	r := func(d time.Duration) time.Duration { return d.Round(100 * time.Millisecond) }
	return fmt.Sprintf("queue %v, slot wait %v, lab start %v, tests %v, teardown %v", r(p.Queue), r(p.SlotWait), r(p.Start), r(p.Tests), r(p.Teardown))
}

// labTimeLine is a node-phase package's line of where its time went.
func labTimeLine(pkg string, elapsed time.Duration, p LabPhases) string {
	return fmt.Sprintf("lab gotest %s: took %v (%v)\n", pkg, elapsed.Round(100*time.Millisecond), p)
}

// labPhases is the phases of a lab run from when it queued for the run's
// lab, when its start began, when its start returned (after waiting
// slotWait of it for a slot), when its tests ended and when its tear-down
// ended; a zero time is a phase never reached.
func labPhases(queued, began, started, tested, down time.Time, slotWait time.Duration) LabPhases {
	span := func(from, to time.Time) time.Duration {
		if from.IsZero() || to.IsZero() {
			return 0
		}
		return max(to.Sub(from), 0)
	}
	p := LabPhases{Queue: span(queued, began), SlotWait: slotWait, Start: max(span(began, started)-slotWait, 0), Tests: span(started, tested)}
	if !tested.IsZero() {
		p.Teardown = span(tested, down)
	} else {
		p.Teardown = span(started, down)
	}
	return p
}

// labTimer times one package's run in a lab node (LabPhases).
type labTimer struct {
	queued, began, started, tested time.Time
	slotWait                       time.Duration
}

// startClock is the clock for the lab's start, which notes its slot wait
// in the timer.
func (t *labTimer) startClock() startClock {
	c := labBudget.begin(time.Time{})
	c.slotWait = &t.slotWait
	return c
}

func (t *labTimer) phases(down time.Time) LabPhases {
	return labPhases(t.queued, t.began, t.started, t.tested, down, t.slotWait)
}

// GoTestConcurrency bounds GoTestEach's packages.
type GoTestConcurrency struct {
	Labs   int // packages running in a lab at once
	Builds int // packages compiling their tests, or checking the cache, at once
	// BuildAllFirst holds every lab back until every package's tests are
	// built, so no compile overlaps a running test (a perf run).
	BuildAllFirst bool
}

// GoTestEach runs each package's tests in a lab node (GoTestTopology).
// The packages share labs, one after another, through a pool of as many
// labs as run at once: after a package, its lab is reset and checked
// (Lab.Reset), so no package sees what another left behind, and a lab
// whose check failed, or whose package failed, is torn down, as is one
// no package left may take; a package with FreshLabFile gets a lab of its
// own. Builds, the CPU-bound part, run
// ahead of the labs, which mostly wait on containers (GoTestConcurrency).
// The pool's count of labs started, packages and labs retired ends w.
// Each package's output goes to w in one
// piece, in the order the packages finish. env (NAME=value) is added to the
// test binaries' environment. With a cache, a package whose recorded pass
// still holds starts no lab and is reported "(cached)", and a package that
// passes is recorded. It returns each package's result, sorted by import
// path; err is for the lab itself failing (a start or tear-down). Its labs run this process's
// binaries: the caller removes them with RemoveRunBinaries once GoTestEach
// returns.
func GoTestEach(ctx context.Context, root string, pkgs []GoPackage, c GoTestConcurrency, w io.Writer, cache *GoTestCache, env []string, args ...string) (results []GoTestResult, err error) {
	if c.Labs < 1 || c.Builds < 1 {
		return nil, fmt.Errorf("lab: %d labs and %d builds at once: want at least one of each", c.Labs, c.Builds)
	}
	checkout, err := CheckoutProject(root)
	if err != nil {
		return nil, err
	}
	run, err := runID()
	if err != nil {
		return nil, err
	}
	pooled := 0
	for _, pkg := range pkgs {
		if !pkg.FreshLab {
			pooled++
		}
	}
	var (
		mu    sync.Mutex
		errs  []error
		wg    sync.WaitGroup
		gates = newGoTestGates(c, len(pkgs))
		pool  = newNodePool(c.Labs, pooled, func(i int) string { return nodePoolProject(checkout, run, i) })
	)
	defer func() { err = errors.Join(err, pool.close(w, "packages")) }()
	for _, pkg := range pkgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out bytes.Buffer
			res, labErr := goTestPackage(ctx, root, ownGoTestPackageProject(checkout, run, pkg.ImportPath), pkg, &out, cache, gates, pool, env, args)
			mu.Lock()
			defer mu.Unlock()
			if labErr != nil {
				errs = append(errs, labErr)
			}
			results = append(results, res)
			_, _ = w.Write(out.Bytes())
		}()
	}
	wg.Wait()
	slices.SortFunc(results, func(a, b GoTestResult) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	return results, errors.Join(errs...)
}

// goTestGates bound GoTestEach's packages: builds, those preparing the
// run, compiling their tests or checking the cache; labs, those running in
// a lab. With BuildAllFirst, allBuilt closes once every package is past
// its build steps.
type goTestGates struct {
	builds, labs chan struct{}
	building     *sync.WaitGroup // nil without BuildAllFirst
	allBuilt     chan struct{}
}

// newGoTestGates makes the gates for packages packages; each of them must
// go through run exactly once.
func newGoTestGates(c GoTestConcurrency, packages int) *goTestGates {
	g := &goTestGates{builds: make(chan struct{}, c.Builds), labs: make(chan struct{}, c.Labs)}
	if c.BuildAllFirst {
		g.building, g.allBuilt = new(sync.WaitGroup), make(chan struct{})
		g.building.Add(packages)
		go func() {
			g.building.Wait()
			close(g.allBuilt)
		}()
	}
	return g
}

// run takes one package through the gates: prepare and build under a build
// token, then, when build says the package needs a lab, inLab under a lab
// token, taken only once the build token is given back (and, with
// BuildAllFirst, once every package is built). inLab gets when the
// package began to queue for its lab token. The error is prepare's, or
// ctx's when it ends while the package waits for a token; build and inLab
// report their own outcomes.
func (g *goTestGates) run(ctx context.Context, prepare func() error, build func() (needsLab bool), inLab func(queued time.Time)) error {
	needsLab, err := g.build(ctx, prepare, build)
	if err != nil || !needsLab {
		return err
	}
	queued := time.Now()
	if g.allBuilt != nil {
		if err := waitGate(ctx, "every package's build", g.allBuilt); err != nil {
			return err
		}
	}
	if err := takeGate(ctx, "a lab", g.labs); err != nil {
		return err
	}
	defer func() { <-g.labs }()
	inLab(queued)
	return nil
}

func (g *goTestGates) build(ctx context.Context, prepare func() error, build func() bool) (needsLab bool, err error) {
	if g.building != nil {
		defer g.building.Done()
	}
	if err := takeGate(ctx, "a build", g.builds); err != nil {
		return false, err
	}
	defer func() { <-g.builds }()
	if err := prepare(); err != nil {
		return false, err
	}
	return build(), nil
}

// takeGate takes a token of gate, unless ctx ends first: a package still
// queued when the run's bound passes starts nothing.
func takeGate(ctx context.Context, what string, gate chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("waiting for %s: %w", what, err)
	}
	select {
	case gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for %s: %w", what, ctx.Err())
	}
}

func waitGate(ctx context.Context, what string, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for %s: %w", what, ctx.Err())
	}
}

// goTestPackage is one package of GoTestEach: served from the cache, or run
// in a lab of pool (in a fresh lab with FreshLab), its output in out.
// project names its lab when fresh. A package without FreshLab that
// doesn't reach the pool is counted out of it (skip).
func goTestPackage(ctx context.Context, root, project string, pkg GoPackage, out *bytes.Buffer, cache *GoTestCache, gates *goTestGates, pool packagePool, env, args []string) (GoTestResult, error) {
	r := &packageRun{ctx: ctx, root: root, project: project, pkg: pkg, out: out, cache: cache, pool: pool, fresh: goTestFresh, env: env, args: args}
	r.res = GoTestResult{ImportPath: pkg.ImportPath}
	defer func() {
		if !pkg.FreshLab && !r.pooled {
			pool.skip()
		}
	}()
	if err := gates.run(ctx, r.prepare, r.build, r.inLab); err != nil {
		if !r.headed {
			r.head("")
		}
		return r.res, fmt.Errorf("lab gotest %s: %w", pkg.ImportPath, err)
	}
	return r.res, r.labErr
}

// packageRun is one package's steps through goTestGates.run.
type packageRun struct {
	ctx           context.Context
	root, project string
	pkg           GoPackage
	out           *bytes.Buffer
	cache         *GoTestCache
	pool          packagePool
	fresh         func(ctx context.Context, queued time.Time, root, project string, pkg GoPackage, w io.Writer, env, args []string, readLog bool) labRun // goTestFresh
	env, args     []string

	p      preparedRun
	entry  *goTestEntry // nil: no cache, or none for this package
	headed bool         // the package's header line is in out
	pooled bool         // it went to the pool
	res    GoTestResult
	labErr error
}

func (r *packageRun) head(suffix string) {
	r.headed = true
	fmt.Fprintln(r.out, "=== lab gotest "+r.pkg.ImportPath+suffix)
}

func (r *packageRun) prepare() (err error) {
	r.p, err = prepare(r.ctx, r.root)
	return err
}

// build compiles the package's tests and looks for a recorded pass; it
// says whether the package still needs a lab.
func (r *packageRun) build() (needsLab bool) {
	name, built, err := buildPackageTests(r.ctx, r.root, r.p.bin.path, r.pkg)
	if err != nil || !built { // !built: no tests for linux, nothing to start a lab for
		r.head("")
		if err != nil {
			fmt.Fprintln(r.out, err)
			r.res.Failed = true
		}
		return false
	}
	if r.cache == nil {
		r.head("")
		return true
	}
	if r.entry, err = r.cache.entry(r.ctx, r.root, r.p, name, r.pkg, r.env, r.args); err != nil {
		r.head("\nlab: results cache: " + err.Error())
		r.entry = nil
		return true
	}
	t, ok := r.cache.Store.Lookup(r.entry.action, r.entry.resolve)
	if !ok {
		r.head("")
		return true
	}
	r.res.Cached, r.res.Tests = true, TestTally{Passed: t.Passed, Skipped: t.Skipped}
	if t == (testcache.Tally{}) { // not verbose: nothing was counted
		r.head(" (cached)")
	} else {
		r.head(fmt.Sprintf(" (cached: %d passed, %d skipped)", t.Passed, t.Skipped))
	}
	return false
}

// inLab runs the package's tests in a lab, the pool's or a fresh one, and
// records a pass. Its time is from when it queued for the lab.
func (r *packageRun) inLab(queued time.Time) {
	started := time.Now()
	runArgs := r.args
	if r.entry != nil {
		runArgs = append(slices.Clone(r.args), "-test.testlogfile="+goTestLogFile)
	}
	start := r.out.Len()
	var run labRun
	if r.pkg.FreshLab {
		run = r.fresh(r.ctx, queued, r.root, r.project, r.pkg, r.out, r.env, runArgs, r.entry != nil)
	} else {
		r.pooled = true
		run = r.pool.goTest(r.ctx, queued, r.root, r.pkg.ImportPath, r.out, testVerbose(r.args), func(n *Node) labRun {
			return runInNode(r.ctx, n, r.pkg, r.out, r.env, runArgs, r.entry != nil)
		})
	}
	r.res.Elapsed = time.Since(queued)
	r.res.Phases = run.phases
	r.res.Failed = run.testErr != nil
	r.res.Tests = TallyTests(r.out.Bytes()[start:])
	if run.testErr != nil {
		fmt.Fprintln(r.out, run.testErr)
	}
	r.out.WriteString(labTimeLine(r.pkg.ImportPath, r.res.Elapsed, r.res.Phases))
	if r.entry != nil {
		if err := r.cache.record(r.entry, run, started, r.res.Tests); err != nil {
			fmt.Fprintf(r.out, "lab: results cache: pass not recorded: %v\n", err)
		}
	}
	r.labErr = run.labErr
}

// goTestLogFile is where, in a gotest node, the test binary writes its
// -test.testlogfile: the files and environment it read.
const goTestLogFile = "/tmp/thinkpol-gotest.testlog"

// goTestLogLimit bounds the test log read back from a node.
const goTestLogLimit = 16 << 20

// readFile reads a file in the node, at most goTestLogLimit bytes of it.
func (n *Node) readFile(ctx context.Context, name string) ([]byte, error) {
	res, err := docker(ctx, "exec", n.Container, "head", "-c", strconv.Itoa(goTestLogLimit+1), name)
	if err != nil {
		return nil, err
	}
	if len(res.Stdout) > goTestLogLimit {
		return nil, fmt.Errorf("%s in %s: over %d bytes", name, n.Name, goTestLogLimit)
	}
	return []byte(res.Stdout), nil
}

// goTestFresh runs a package's tests in a fresh lab and, with readLog and
// the tests passed, reads their -test.testlogfile back before the lab goes.
// It times the run's phases (LabPhases), from queued, when the package
// began to queue for its lab.
func goTestFresh(ctx context.Context, queued time.Time, root, project string, pkg GoPackage, w io.Writer, env, args []string, readLog bool) (run labRun) {
	timer := labTimer{queued: queued, began: time.Now()}
	l, err := up(ctx, timer.startClock(), root, project, GoTestTopology(), "", runInputs)
	timer.started = time.Now()
	defer func() {
		if l != nil {
			if err := l.Down(context.WithoutCancel(ctx)); err != nil && run.labErr == nil {
				run.labErr = err
			}
		}
		run.phases = timer.phases(time.Now())
	}()
	if err != nil {
		run.labErr = err
		return run
	}
	run = runInNode(ctx, l.Node("gotest"), pkg, w, env, args, readLog)
	timer.tested = time.Now()
	return run
}

// runInNode runs a package's tests in n and, with readLog and the tests
// passed, reads their -test.testlogfile back.
func runInNode(ctx context.Context, n *Node, pkg GoPackage, w io.Writer, env, args []string, readLog bool) (run labRun) {
	run.testErr = n.goTest(ctx, w, pkg, env, args)
	if readLog && run.testErr == nil {
		run.testLog, run.logErr = n.readFile(ctx, goTestLogFile)
	}
	return run
}

// GoTestTopology is the lab GoTest runs packages in when no topology is
// given: one node on one network, no default route. Tests build whatever
// they need (namespaces, veths, TUNs) inside it.
func GoTestTopology() Topology {
	return Topology{
		Networks: []Network{{Name: "lab"}},
		Nodes:    []NodeSpec{{Name: "gotest", Networks: []string{"lab"}}},
	}
}

// ListLabTaggedPackages expands go package patterns, as seen for this
// machine, to the packages that have test files behind the lab build tag:
// lab tests, which start labs from the host and need Docker there, not in
// a node.
func ListLabTaggedPackages(ctx context.Context, root string, patterns ...string) ([]GoPackage, error) {
	untagged, err := listTestFiles(ctx, root, nil, patterns)
	if err != nil {
		return nil, err
	}
	tagged, err := listTestFiles(ctx, root, []string{"-tags=lab"}, patterns)
	if err != nil {
		return nil, err
	}
	var out []GoPackage
	// Names, not counts: a !lab test file can pair with a lab one.
	for _, p := range tagged {
		plain := untagged[p.ImportPath].testFiles
		if slices.ContainsFunc(p.testFiles, func(f string) bool { return !slices.Contains(plain, f) }) {
			out = append(out, p.GoPackage)
		}
	}
	slices.SortFunc(out, func(a, b GoPackage) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	return out, nil
}

type listedPackage struct {
	GoPackage
	testFiles []string
}

func listTestFiles(ctx context.Context, root string, flags, patterns []string) (map[string]listedPackage, error) {
	args := append(append([]string{"-C", root, "list", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles"}, flags...), patterns...)
	res, err := run(ctx, nil, nil, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	out := map[string]listedPackage{}
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	for dec.More() {
		var p struct {
			ImportPath                string
			Dir                       string
			TestGoFiles, XTestGoFiles []string
		}
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return nil, err
		}
		out[p.ImportPath] = listedPackage{
			GoPackage: GoPackage{ImportPath: p.ImportPath, Dir: filepath.ToSlash(rel)},
			testFiles: slices.Concat(p.TestGoFiles, p.XTestGoFiles),
		}
	}
	return out, nil
}

// DefaultLabTestTimeout bounds a package's lab tests (GoTestLabTagged)
// unless the caller passes its own -test.timeout; it matches make lab-test's
// LAB_TIMEOUT.
const DefaultLabTestTimeout = "60m"

// labTestWaitDelay bounds how long GoTestLabTagged waits for the output
// pipe to close once its go test has exited or been killed.
const labTestWaitDelay = 10 * time.Second

// GoTestLabTagged runs a package's tests on this machine with the lab build
// tag, as make lab-test runs ./lab/...: its lab tests start their own labs
// and run in-node tests there, and its tests without the tag run too. args
// are test binary flags (-test.v, -test.run, ...); env (NAME=value) is
// added to the environment. Output is streamed to w; the error is non-nil
// when the tests fail. Cancelling ctx kills go test and every process it
// started; the labs its tests started stay up (make lab-down removes them).
func GoTestLabTagged(ctx context.Context, root string, pkg GoPackage, w io.Writer, env []string, args ...string) (GoTestResult, error) {
	if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(strings.TrimLeft(a, "-"), "test.timeout") }) {
		args = append([]string{"-test.timeout=" + DefaultLabTestTimeout}, args...)
	}
	// -count=1 before the package: a later -test.count from args wins, and
	// either way the result is never served from the test cache.
	cmd := exec.CommandContext(ctx, "go", append([]string{"-C", root, "test", "-tags=lab", "-count=1", "./" + pkg.Dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	killGroupOnCancel(cmd)
	// A process that left the group may still hold the output pipe.
	cmd.WaitDelay = labTestWaitDelay
	var out syncBuffer
	cmd.Stdout = io.MultiWriter(w, &out)
	cmd.Stderr = cmd.Stdout
	started := time.Now()
	err := cmd.Run()
	res := GoTestResult{ImportPath: pkg.ImportPath, Failed: err != nil, Tests: TallyTests([]byte(out.String())), Elapsed: time.Since(started)}
	if err != nil {
		return res, fmt.Errorf("lab: lab tests in %s: %w", pkg.ImportPath, err)
	}
	return res, nil
}

// TestTally counts a verbose (-test.v) test run's top-level tests by
// outcome. Subtests, and test output nested in a lab test's log (indented),
// don't count.
type TestTally struct {
	Passed, Failed, Skipped int
}

// TallyTests tallies the "--- PASS/FAIL/SKIP: " lines that start a line in
// a verbose test run's output.
func TallyTests(out []byte) TestTally {
	var t TestTally
	for line := range strings.Lines(string(out)) {
		switch {
		case strings.HasPrefix(line, "--- PASS: "):
			t.Passed++
		case strings.HasPrefix(line, "--- FAIL: "):
			t.Failed++
		case strings.HasPrefix(line, "--- SKIP: "):
			t.Skipped++
		}
	}
	return t
}

// Ran is how many tests ran, skipped ones included.
func (t TestTally) Ran() int { return t.Passed + t.Failed + t.Skipped }

// OnlySkipped returns, sorted, the packages in which at least one test ran
// and every test that ran, over all of a package's results, skipped.
func OnlySkipped(results []GoTestResult) []string {
	byPkg := map[string]TestTally{}
	for _, r := range results {
		t := byPkg[r.ImportPath]
		t.Passed += r.Tests.Passed
		t.Failed += r.Tests.Failed
		t.Skipped += r.Tests.Skipped
		byPkg[r.ImportPath] = t
	}
	var out []string
	for pkg, t := range byPkg {
		if t.Skipped > 0 && t.Passed+t.Failed == 0 {
			out = append(out, pkg)
		}
	}
	slices.Sort(out)
	return out
}
