// Command labctl drives the lab from make: lab-up, lab-down, lab-gotest and
// the in-node half of lab-test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/testcache"
)

const usage = `usage: labctl <command>

  up                                  start the standard topology for this checkout
  down [-tests | -run id | -stale]    remove this checkout's labs and ended runs' binaries (-tests:
                                      only the labs tests started; -run: only those the run id
                                      started; -stale: instead, every lab whose checkout is gone,
                                      and no binaries)
  gotest [-v] [-run re] [-skip re] [-count n] [-timeout d] [-p n] [-perf] [-tagged] [-fail-skipped]
         [-times file] pkgs...
                                      run each package's tests in a fresh lab node with THINKPOL_LAB=1
                                      (-run, -skip, -count, -timeout: the test binary's; -count repeats
                                      runs for stability)
                                      (-times: write how long each package took, lab setup included,
                                      for labctl budget)
                                      (-perf: alone on the host, with THINKPOL_LAB_PERF=1: make lab-perf)
                                      (-tagged: then run packages with lab-tagged tests on the host,
                                      go test -tags lab, as make lab-test's lab phase does)
                                      (-fail-skipped: implies -v; fail a package whose tests all
                                      skipped, and a run in which no test ran: make lab-gotest)
                                      (a package whose recorded pass still holds is not run but
                                      reported "(cached)"; -count, -perf or ` + testcache.NoCacheEnv + `=1 run
                                      every package and record nothing)
  project                             print this checkout's project prefix
  run-id                              print a fresh run id, for ` + lab.RunEnv + `
  testjson -times file                read go test -json on stdin, print what go test without -v would
                                      have, write how long each test took to file
  budget -stream name -since unix [-budget d] [-top n] files...
                                      say how long a stream has taken since its start (unix seconds)
                                      and, with -budget, fail when it took longer, listing the slowest
                                      tests in the -times files (make lab-test's LAB_BUDGET)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command")
	}
	root, err := lab.Root()
	if err != nil {
		return err
	}
	switch args[0] {
	case "up":
		ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		return up(ctx, root)
	case "down":
		return down(ctx, root, args[1:])
	case "gotest":
		return runGotest(ctx, root, args[1:])
	case "testjson":
		return testJSON(os.Stdin, os.Stdout, args[1:])
	case "budget":
		return budget(os.Stdout, time.Now(), args[1:])
	case "project":
		checkout, err := lab.CheckoutProject(root)
		if err != nil {
			return err
		}
		fmt.Println(checkout)
		return nil
	case "run-id":
		fmt.Println(lab.NewRunID())
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// down removes this checkout's labs (or only its tests', or one run's, or
// every stale one) and prints what it removed.
func down(ctx context.Context, root string, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	onlyTests := fs.Bool("tests", false, "only remove labs started by tests")
	run := fs.String("run", "", "only remove labs the run with this id started ("+lab.RunEnv+")")
	stale := fs.Bool("stale", false, "remove every lab whose checkout no longer exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Parsing stops at the first argument that isn't a flag: "down r1 -run
	// r1" would leave -run unseen and remove the whole checkout's labs.
	if fs.NArg() > 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("down: unexpected argument %q", fs.Arg(0))
	}
	// -run given at all means one run's labs, even with an empty or invalid
	// id (an unset variable): never the whole checkout's.
	runGiven := false
	fs.Visit(func(f *flag.Flag) { runGiven = runGiven || f.Name == "run" })
	if n := btoi(*onlyTests) + btoi(runGiven) + btoi(*stale); n > 1 {
		return errors.New("down: -tests, -run and -stale don't combine")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var removed []string
	var err error
	switch {
	case *stale:
		removed, err = lab.DownStale(ctx)
	case runGiven:
		removed, err = lab.DownRun(ctx, root, *run)
	default:
		removed, err = lab.DownCheckout(ctx, root, *onlyTests)
	}
	for _, p := range removed {
		fmt.Println("removed", p)
	}
	return err
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// runGotest parses gotest's flags into the test binary's, and runs it.
func runGotest(ctx context.Context, root string, args []string) (err error) {
	// The binaries its labs ran; every one of them is down by now.
	defer func() { err = errors.Join(err, lab.RemoveRunBinaries(context.WithoutCancel(ctx))) }()
	fs := flag.NewFlagSet("gotest", flag.ContinueOnError)
	runRe := fs.String("run", "", "run only tests matching the regexp")
	skipRe := fs.String("skip", "", "skip tests matching the regexp")
	count := fs.Int("count", 0, "run each test n times (the test binary's -test.count)")
	timeout := fs.String("timeout", "", "the test binary's -test.timeout (default "+lab.DefaultTestTimeout+" in a node, "+lab.DefaultLabTestTimeout+" on the host with -tagged)")
	verbose := fs.Bool("v", false, "verbose test output")
	parallel := fs.Int("p", 4, "packages tested at once")
	perf := fs.Bool("perf", false, "a perf run: wait until no other lab runs, keep others from starting, set "+lab.PerfEnv+"=1")
	tagged := fs.Bool("tagged", false, "also run packages with lab-tagged tests on the host (go test -tags lab)")
	failSkipped := fs.Bool("fail-skipped", false, "fail a package whose tests all skipped, and a run in which no test ran (implies -v)")
	times := fs.String("times", "", "write how long each package took to this file (labctl budget)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runFor, err := gotestRunFor(*timeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, runFor)
	defer cancel()
	var env []string
	if *perf {
		fmt.Println("gotest: waiting until no other lab runs")
		release, err := lab.AcquirePerfLock(ctx)
		if err != nil {
			return err
		}
		defer release()
		env = append(env, lab.PerfEnv+"=1")
	}
	var testArgs []string
	if *verbose || *failSkipped {
		testArgs = append(testArgs, "-test.v")
	}
	if *runRe != "" {
		testArgs = append(testArgs, "-test.run", *runRe)
	}
	if *skipRe != "" {
		testArgs = append(testArgs, "-test.skip", *skipRe)
	}
	if *count > 0 {
		testArgs = append(testArgs, fmt.Sprintf("-test.count=%d", *count))
	}
	if *timeout != "" {
		testArgs = append(testArgs, "-test.timeout="+*timeout)
	}
	opt := gotestOptions{parallel: *parallel, tagged: *tagged, failSkipped: *failSkipped, times: *times}
	if useCache(*count, *perf) {
		opt.cache = lab.NewGoTestCache(os.Stdout)
	}
	return gotest(ctx, root, opt, env, testArgs, fs.Args())
}

// gotestRunFor bounds a whole gotest run: an hour, or longer when the
// test binaries' own -timeout asks for more (make lab-gotest's LAB_TIMEOUT),
// so the run's bound never cuts a test short of its own.
func gotestRunFor(timeout string) (time.Duration, error) {
	const atLeast, beyondTests = 60 * time.Minute, 15 * time.Minute
	if timeout == "" {
		return atLeast, nil
	}
	d, err := time.ParseDuration(timeout)
	if err != nil {
		return 0, fmt.Errorf("gotest: -timeout: %w", err)
	}
	return max(atLeast, d+beyondTests), nil
}

// useCache says whether a gotest run may serve packages from the results
// cache and record passes: not when it repeats tests (-count, -count=1
// included) or measures them (-perf), nor with testcache.NoCacheEnv set.
func useCache(count int, perf bool) bool {
	return os.Getenv(testcache.NoCacheEnv) == "" && count == 0 && !perf
}

func up(ctx context.Context, root string) error {
	checkout, err := lab.CheckoutProject(root)
	if err != nil {
		return err
	}
	l, err := lab.UpDetached(ctx, root, checkout, lab.Standard())
	if err != nil {
		if l != nil {
			err = errors.Join(err, l.Down(context.WithoutCancel(ctx)))
		}
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NODE\tNETWORK\tIPV4\tIPV6")
	for _, spec := range l.Topology.Nodes {
		for _, net := range spec.Networks {
			a := l.Node(spec.Name).Addr(net)
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", spec.Name, net, a.IPv4, a.IPv6)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	file, err := filepath.Rel(root, l.ComposeFile())
	if err != nil {
		return err
	}
	fmt.Printf("\nlab %s is up (compose file %s)\n", l.Project, file)
	fmt.Printf("shell: docker compose -p %s exec %s bash; make lab-down removes it\n", l.Project, lab.DeviceA)
	return nil
}

type gotestOptions struct {
	parallel            int
	tagged, failSkipped bool
	times               string           // the file to write each package's time to; "": none
	cache               *lab.GoTestCache // nil: run every package
}

func gotest(ctx context.Context, root string, opt gotestOptions, env, args, patterns []string) error {
	if len(patterns) == 0 {
		return errors.New("gotest: no packages")
	}
	pkgs, err := lab.ListGoPackages(ctx, root, patterns...)
	if err != nil {
		return err
	}
	var tagged []lab.GoPackage
	if opt.tagged {
		if tagged, err = lab.ListLabTaggedPackages(ctx, root, patterns...); err != nil {
			return err
		}
	}
	if len(pkgs)+len(tagged) == 0 {
		if opt.failSkipped {
			return errors.New("gotest: no packages with tests")
		}
		fmt.Println("gotest: no packages with tests")
		return nil
	}
	var results []lab.GoTestResult
	if len(pkgs) > 0 {
		if results, err = lab.GoTestEach(ctx, root, pkgs, opt.parallel, os.Stdout, opt.cache, env, args...); err != nil {
			return err
		}
	}
	for _, pkg := range tagged {
		fmt.Printf("=== lab gotest -tags lab (on the host) %s\n", pkg.ImportPath)
		res, err := lab.GoTestLabTagged(ctx, root, pkg, os.Stdout, env, args...)
		if err != nil {
			fmt.Println(err)
		}
		results = append(results, res)
	}
	if opt.times != "" {
		var times []lab.TestTime
		for _, r := range results {
			if !r.Cached {
				times = append(times, lab.TestTime{Name: r.ImportPath, Elapsed: r.Elapsed})
			}
		}
		if err := lab.WriteTestTimes(opt.times, times); err != nil {
			return errors.Join(gotestVerdict(results, opt.failSkipped), err)
		}
	}
	return gotestVerdict(results, opt.failSkipped)
}

// testJSON filters go test -json from r into what go test would have
// printed without -v, and writes each test's time to -times.
func testJSON(r io.Reader, w io.Writer, args []string) error {
	fs := flag.NewFlagSet("testjson", flag.ContinueOnError)
	times := fs.String("times", "", "write how long each test took to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *times == "" || fs.NArg() > 0 {
		return errors.New("testjson: want -times file and no arguments")
	}
	got, err := lab.FilterTestJSON(r, w)
	// Whatever was read is written: a time file missing makes the budget's
	// report miss tests, not pass.
	return errors.Join(err, lab.WriteTestTimes(*times, got))
}

// budget reports how long a stream took, from its start to now, and fails
// it when that is over its budget.
func budget(w io.Writer, now time.Time, args []string) error {
	fs := flag.NewFlagSet("budget", flag.ContinueOnError)
	stream := fs.String("stream", "", "the stream's name, for the report")
	since := fs.Int64("since", 0, "the stream's start, in unix seconds")
	limit := fs.Duration("budget", 0, "fail when the stream took longer (0: only report)")
	top := fs.Int("top", 10, "slowest tests listed when over budget")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stream == "" || *since <= 0 {
		return errors.New("budget: want -stream and -since")
	}
	var times []lab.TestTime
	var errs []error
	for _, f := range fs.Args() {
		t, err := lab.ReadTestTimes(f)
		if err != nil {
			// A phase that died writes none: its stream fails on its own
			// status, and the report says what it is missing.
			errs = append(errs, err)
			continue
		}
		times = append(times, t...)
	}
	err := lab.CheckBudget(w, *stream, now.Sub(time.Unix(*since, 0)), *limit, times, *top)
	if err != nil && len(errs) > 0 {
		err = errors.Join(err, fmt.Errorf("budget: the report misses tests: %w", errors.Join(errs...)))
	}
	return err
}

// gotestVerdict is the run's outcome: the packages that failed and, with
// failSkipped, those whose tests all skipped; a run whose test binaries
// were not verbose has nothing to count, so failSkipped needs -test.v.
func gotestVerdict(results []lab.GoTestResult, failSkipped bool) error {
	var failed []string
	ran, pkgs, cached := 0, map[string]bool{}, 0
	for _, r := range results {
		pkgs[r.ImportPath] = true
		ran += r.Tests.Ran()
		if r.Cached {
			cached++
		}
		if r.Failed && !slices.Contains(failed, r.ImportPath) {
			failed = append(failed, r.ImportPath)
		}
	}
	slices.Sort(failed)
	var errs []error
	if len(failed) > 0 {
		errs = append(errs, fmt.Errorf("gotest: failed: %s", strings.Join(failed, " ")))
	}
	if failSkipped {
		if skipped := lab.OnlySkipped(results); len(skipped) > 0 {
			errs = append(errs, fmt.Errorf("gotest: every test skipped in: %s", strings.Join(skipped, " ")))
		}
		if ran == 0 {
			errs = append(errs, errors.New("gotest: no test ran"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Printf("gotest: ok, %d packages, %d of them cached\n", len(pkgs), cached)
	return nil
}
