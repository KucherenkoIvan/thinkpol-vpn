//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "devicetest runs on macOS (and in the lab, on Linux) only")
	os.Exit(2)
}
