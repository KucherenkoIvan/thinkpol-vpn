//go:build !darwin && !linux

// Command devicetest-root is the device-test harness's root side.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "devicetest-root runs on macOS (and in the lab, on Linux) only")
	os.Exit(2)
}
