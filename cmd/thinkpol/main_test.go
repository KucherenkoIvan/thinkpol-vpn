package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionPrintsVersion(t *testing.T) {
	code, stdout, stderr := runCLI(t, "version")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	fields := strings.Fields(stdout)
	if len(fields) != 4 || fields[0] != "thinkpol" || fields[1] == "" {
		t.Fatalf("unexpected output %q", stdout)
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	code, _, stderr := runCLI(t, "version", "extra")
	if code != 2 || !strings.Contains(stderr, "usage:") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	code, _, stderr := runCLI(t, "nope")
	if code != 2 || !strings.Contains(stderr, `unknown command "nope"`) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestNoCommandPrintsUsage(t *testing.T) {
	code, _, stderr := runCLI(t)
	if code != 2 || !strings.Contains(stderr, "version") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestHelpListsCommands(t *testing.T) {
	code, stdout, _ := runCLI(t, "help")
	if code != 0 || !strings.Contains(stdout, "version") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
}
