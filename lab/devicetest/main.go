//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plans"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

const usage = `devicetest: the device-test harness (run by the owner only)

  devicetest plans [TICKET]    list the plans, or print one plan's steps
  devicetest run TICKET [-iface IF] [-thinkpol PATH] [-evidence DIR]
                               self-test, then the plan's steps, then the restore
  devicetest selftest [-iface IF]
                               the self-test alone
  devicetest restore           finish an unfinished run from its journal
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := dispatch(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "devicetest:", err)
		os.Exit(1)
	}
}

func dispatch(mode string, args []string) error {
	ctx := context.Background()
	root := safety.StateConfig{Dir: safety.DefaultStateDir}
	switch mode {
	// The root modes: the launch script (or the helper) starts these.
	case "helper":
		return safety.HelperMain(ctx, args, root, os.Stdin, os.Stdout, os.Stderr)
	case "deadman":
		signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
		return safety.DeadmanMain(ctx, args, root)
	case "root-restore":
		return safety.RestoreMain(ctx, args, root, os.Stdout)
	}
	// The owner's commands run as the owner: as root the evidence would
	// turn root's. Only the helper is root, started with one sudo.
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
