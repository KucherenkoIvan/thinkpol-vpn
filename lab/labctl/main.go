// Command labctl drives the lab from make: lab-up, lab-down, lab-gotest and
// the in-node half of lab-test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

const usage = `usage: labctl <command>

  up                                  start the standard topology for this checkout
  down [-tests | -stale]              remove this checkout's labs and ended runs' binaries (-tests:
                                      only the labs tests started; -stale: instead, every lab whose
                                      checkout is gone, and no binaries)
  gotest [-v] [-run re] [-count n] [-timeout d] [-p n] [-perf] [-tagged] [-fail-skipped] pkgs...
                                      run each package's tests in a fresh lab node with THINKPOL_LAB=1
                                      (-count, -timeout: the test binary's; repeat runs for stability)
                                      (-perf: alone on the host, with THINKPOL_LAB_PERF=1: make lab-perf)
                                      (-tagged: then run packages with lab-tagged tests on the host,
                                      go test -tags lab, as make lab-test's lab phase does)
                                      (-fail-skipped: implies -v; fail a package whose tests all
                                      skipped, and a run in which no test ran: make lab-gotest)
  project                             print this checkout's project prefix
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
	case "project":
		checkout, err := lab.CheckoutProject(root)
		if err != nil {
			return err
		}
		fmt.Println(checkout)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// down removes this checkout's labs (or only its tests', or every stale
// one) and prints what it removed.
func down(ctx context.Context, root string, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	onlyTests := fs.Bool("tests", false, "only remove labs started by tests")
	stale := fs.Bool("stale", false, "remove every lab whose checkout no longer exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var removed []string
	var err error
	if *stale {
		removed, err = lab.DownStale(ctx)
	} else {
		removed, err = lab.DownCheckout(ctx, root, *onlyTests)
	}
	for _, p := range removed {
		fmt.Println("removed", p)
	}
	return err
}

// runGotest parses gotest's flags into the test binary's, and runs it.
func runGotest(ctx context.Context, root string, args []string) (err error) {
	// The binaries its labs ran; every one of them is down by now.
	defer func() { err = errors.Join(err, lab.RemoveRunBinaries(context.WithoutCancel(ctx))) }()
	fs := flag.NewFlagSet("gotest", flag.ContinueOnError)
	runRe := fs.String("run", "", "run only tests matching the regexp")
	count := fs.Int("count", 0, "run each test n times (the test binary's -test.count)")
	timeout := fs.String("timeout", "", "the test binary's -test.timeout (default "+lab.DefaultTestTimeout+")")
	verbose := fs.Bool("v", false, "verbose test output")
	parallel := fs.Int("p", 4, "packages tested at once")
	perf := fs.Bool("perf", false, "a perf run: wait until no other lab runs, keep others from starting, set "+lab.PerfEnv+"=1")
	tagged := fs.Bool("tagged", false, "also run packages with lab-tagged tests on the host (go test -tags lab)")
	failSkipped := fs.Bool("fail-skipped", false, "fail a package whose tests all skipped, and a run in which no test ran (implies -v)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
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
	if *count > 0 {
		testArgs = append(testArgs, fmt.Sprintf("-test.count=%d", *count))
	}
	if *timeout != "" {
		testArgs = append(testArgs, "-test.timeout="+*timeout)
	}
	return gotest(ctx, root, gotestOptions{parallel: *parallel, tagged: *tagged, failSkipped: *failSkipped}, env, testArgs, fs.Args())
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
		if results, err = lab.GoTestEach(ctx, root, pkgs, opt.parallel, os.Stdout, env, args...); err != nil {
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
	return gotestVerdict(results, opt.failSkipped)
}

// gotestVerdict is the run's outcome: the packages that failed and, with
// failSkipped, those whose tests all skipped; a run whose test binaries
// were not verbose has nothing to count, so failSkipped needs -test.v.
func gotestVerdict(results []lab.GoTestResult, failSkipped bool) error {
	var failed []string
	ran, pkgs := 0, map[string]bool{}
	for _, r := range results {
		pkgs[r.ImportPath] = true
		ran += r.Tests.Ran()
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
	fmt.Printf("gotest: ok, %d packages\n", len(pkgs))
	return nil
}
