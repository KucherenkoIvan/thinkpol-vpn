//go:build darwin || linux

// Command devicetest-root is the device-test harness's root side: the
// helper, the dead-man and root-restore, the safety core's modes and
// nothing else. devicetest starts it through the launch script (sudo, a
// hash-checked root copy); it links no plan, so no plan code runs as root.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "devicetest-root: started by devicetest, never by hand")
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch mode, args := os.Args[1], os.Args[2:]; mode {
	case "helper":
		err = safety.HelperMain(ctx, args, os.Stdin, os.Stdout, os.Stderr)
	case "deadman":
		err = safety.DeadmanMain(ctx, args)
	case "root-restore":
		err = safety.RestoreMain(ctx, args, os.Stdout)
	default:
		err = fmt.Errorf("no mode %q", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "devicetest-root:", err)
		os.Exit(1)
	}
}
