// Command labctl drives the lab from make: lab-up, lab-down, lab-gotest and
// the in-node half of lab-test.
// Tests don't need it; they start their own labs through package lab.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

const usage = `usage: labctl <command>

  up                             start the standard topology for this checkout
  down [-tests]                  remove this checkout's labs (-tests: only the ones tests started)
  gotest [-v] [-run re] pkgs...  run the packages' tests in a lab node with THINKPOL_LAB=1
  project                        print this checkout's project prefix
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
	checkout := lab.CheckoutProject(root)
	switch args[0] {
	case "up":
		return up(ctx, root, checkout)
	case "down":
		fs := flag.NewFlagSet("down", flag.ContinueOnError)
		onlyTests := fs.Bool("tests", false, "only remove labs started by tests")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		removed, err := lab.DownCheckout(ctx, root, checkout, *onlyTests)
		for _, p := range removed {
			fmt.Println("removed", p)
		}
		return err
	case "gotest":
		fs := flag.NewFlagSet("gotest", flag.ContinueOnError)
		runRe := fs.String("run", "", "run only tests matching the regexp")
		verbose := fs.Bool("v", false, "verbose test output")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return gotest(ctx, root, checkout, *runRe, *verbose, fs.Args())
	case "project":
		fmt.Println(checkout)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func up(ctx context.Context, root, checkout string) error {
	l, err := lab.Up(ctx, root, checkout, lab.Standard())
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NODE\tNETWORK\tIPV4\tIPV6")
	for _, n := range l.Nodes() {
		for _, spec := range l.Topology.Nodes {
			if spec.Name != n.Name {
				continue
			}
			for _, net := range spec.Networks {
				a := n.Addr(net)
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", n.Name, net, a.IPv4, a.IPv6)
			}
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

func gotest(ctx context.Context, root, checkout, runRe string, verbose bool, patterns []string) error {
	if len(patterns) == 0 {
		return errors.New("gotest: no packages")
	}
	pkgs, err := lab.ListGoPackages(ctx, root, patterns...)
	if err != nil {
		return err
	}
	if len(pkgs) == 0 {
		fmt.Println("gotest: no packages with tests")
		return nil
	}
	l, err := lab.Up(ctx, root, lab.GoTestProject(checkout), lab.GoTestTopology())
	if l != nil {
		defer func() { _ = l.Down(context.WithoutCancel(ctx)) }()
	}
	if err != nil {
		return err
	}
	node := l.Node("gotest")
	var args []string
	if verbose {
		args = append(args, "-test.v")
	}
	if runRe != "" {
		args = append(args, "-test.run", runRe)
	}
	var failed []string
	for _, pkg := range pkgs {
		fmt.Printf("=== lab gotest %s\n", pkg.ImportPath)
		if err := node.GoTest(ctx, os.Stdout, pkg, args...); err != nil {
			fmt.Println(err)
			failed = append(failed, pkg.ImportPath)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("gotest: failed: %s", strings.Join(failed, " "))
	}
	fmt.Printf("gotest: ok, %d packages\n", len(pkgs))
	return nil
}
