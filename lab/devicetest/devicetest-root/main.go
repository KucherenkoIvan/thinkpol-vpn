//go:build darwin || linux

// Command devicetest-root is the device-test harness's root side: the
// helper, the dead-man and root-restore, the safety core's modes and
// nothing else. devicetest starts it through the launch script (sudo, a
// hash-checked root copy); it links no plan, so no plan code runs as root.
package main

import (
	"context"
	"os"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

func main() {
	os.Exit(safety.RootMain(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
