package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"testing"
)

// Commands of the "t" group are registered from two files, the way two
// tickets add `dev …` commands without touching each other.
func init() {
	register(command{path: "t a", args: "[-n count]", summary: "test command a", run: runTA})
	register(command{path: "t hidden", summary: "test command, hidden", hidden: true, run: runTA})
}

func runTA(_ context.Context, e env, args []string) error {
	fs := flag.NewFlagSet("t a", flag.ContinueOnError)
	n := fs.Int("n", 1, "how many times")
	if err := parseFlags(fs, e, args); err != nil {
		return err
	}
	_, err := fmt.Fprintf(e.stdout, "a %d %s\n", *n, strings.Join(fs.Args(), ","))
	return err
}

func TestGroupDispatchesToCommand(t *testing.T) {
	code, stdout, stderr := runCLI(t, "t", "a", "-n", "3", "x")
	if code != 0 || stdout != "a 3 x\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestHiddenCommandRuns(t *testing.T) {
	if code, stdout, _ := runCLI(t, "t", "hidden"); code != 0 || stdout != "a 1 \n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}

func TestGroupPrefixListsItsCommands(t *testing.T) {
	code, _, stderr := runCLI(t, "t")
	if code != 2 || !strings.Contains(stderr, "usage: thinkpol t <command>") ||
		!strings.Contains(stderr, "  t a") || !strings.Contains(stderr, "  t b") ||
		strings.Contains(stderr, "version") || strings.Contains(stderr, "t hidden") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestUnknownCommandInGroup(t *testing.T) {
	code, _, stderr := runCLI(t, "t", "c")
	if code != 2 || !strings.Contains(stderr, `unknown command "t c"`) || !strings.Contains(stderr, "  t b") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestFlagHelpExitsZero(t *testing.T) {
	code, _, stderr := runCLI(t, "t", "a", "-h")
	if code != 0 || !strings.HasPrefix(stderr, "usage: thinkpol t a [-n count]") || !strings.Contains(stderr, "how many times") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestBadFlagIsUsageError(t *testing.T) {
	code, _, stderr := runCLI(t, "t", "a", "-bogus")
	if code != 2 || !strings.Contains(stderr, "-bogus") || strings.Count(stderr, "usage: thinkpol t a") != 1 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
