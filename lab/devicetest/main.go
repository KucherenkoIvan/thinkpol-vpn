//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plans"
)

const usage = `devicetest: the device-test harness (run by the owner only)

  devicetest plans [TICKET]
        list the plans, or print everything one plan's run may do
  devicetest run TICKET [-iface IF] [-thinkpol PATH] [-evidence DIR]
        the self-test, then the plan's steps, then the restore
        -iface IF        the physical interface (default: the IPv4 default route's)
        -thinkpol PATH   a thinkpol binary: thinkpol diag is saved after each step
        -evidence DIR    where evidence folders go (default ~/thinkpol-evidence)
  devicetest selftest [-iface IF] [-thinkpol PATH] [-evidence DIR]
        the self-test alone
  devicetest restore
        restore the run pending a restore (unfinished, or left not CLEAN)

devicetest-root, built beside devicetest, is its root side: sudo runs a
checked copy of it.
`

// errReported is an error already written to the terminal and the
// transcript: main doesn't print it again.
var errReported = errors.New("reported")

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := dispatch(context.Background(), os.Args[1], os.Args[2:]); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "devicetest:", err)
		}
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, mode string, args []string) error {
	// The owner's commands run as the owner: as root the evidence would
	// turn root's. Only devicetest-root runs as root, started with sudo.
	if os.Geteuid() == 0 {
		return errors.New("run devicetest as yourself, not as root: it asks for sudo itself")
	}
	switch mode {
	case "plans":
		return cmdPlans(args)
	case "run":
		return cmdRun(ctx, args)
	case "selftest":
		return cmdRun(ctx, append([]string{"selftest"}, args...))
	case "restore":
		return cmdRestore()
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("no command %q", mode)
}

// rootBinary is devicetest-root, beside this binary.
func rootBinary() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	p := filepath.Join(filepath.Dir(self), "devicetest-root")
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: build it beside devicetest (go build -o DIR/ ./lab/devicetest ./lab/devicetest/devicetest-root)", p)
	}
	return p, nil
}

var allPlans = plans.All
