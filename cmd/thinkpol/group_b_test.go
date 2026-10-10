package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func init() {
	register(command{path: "t b", args: "<word>...", summary: "test command b", run: runTB})
}

func runTB(_ context.Context, e env, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	if args[0] == "fail" {
		return errors.New("boom")
	}
	_, err := fmt.Fprintf(e.stdout, "b %s\n", strings.Join(args, ","))
	return err
}

func TestSecondFileInGroupDispatches(t *testing.T) {
	if code, stdout, _ := runCLI(t, "t", "b", "x", "y z"); code != 0 || stdout != "b x,y z\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestCommandUsageErrorPrintsItsSynopsis(t *testing.T) {
	code, _, stderr := runCLI(t, "t", "b")
	if code != 2 || stderr != "usage: thinkpol t b <word>...\n\ntest command b\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestCommandErrorExitsOne(t *testing.T) {
	code, _, stderr := runCLI(t, "t", "b", "fail")
	if code != 1 || stderr != "thinkpol t b: boom\n" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
