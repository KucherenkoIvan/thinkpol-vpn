package main

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), env{stdin: strings.NewReader(""), stdout: &out, stderr: &errOut}, args)
	return code, out.String(), errOut.String()
}

func TestVersionPrintsVersion(t *testing.T) {
	code, stdout, stderr := runCLI(t, "version")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.HasPrefix(stdout, "thinkpol ") || !strings.HasSuffix(stdout, " "+runtime.GOOS+"/"+runtime.GOARCH+"\n") {
		t.Fatalf("unexpected output %q", stdout)
	}
}

func TestVersionComesFromLinkerFlag(t *testing.T) {
	defer func(v string) { version = v }(version)
	version = "v1.2.3"
	if _, stdout, _ := runCLI(t, "version"); !strings.HasPrefix(stdout, "thinkpol v1.2.3 ") {
		t.Fatalf("unexpected output %q", stdout)
	}
}

func TestVersionFallsBackToDev(t *testing.T) {
	defer func(v string) { version = v }(version)
	version = ""
	// test binaries carry no VCS version, as with `go run`
	if got := resolveVersion(); got != "dev" {
		t.Fatalf("resolveVersion() = %q, want dev", got)
	}
}

func TestUsageErrorPrintsCommandSynopsis(t *testing.T) {
	code, _, stderr := runCLI(t, "version", "extra")
	if code != 2 || !strings.HasPrefix(stderr, "usage: thinkpol version\n") {
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
	if code != 2 || !strings.Contains(stderr, "  version") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestHelpListsVisibleCommands(t *testing.T) {
	code, stdout, _ := runCLI(t, "help")
	if code != 0 || !strings.Contains(stdout, "  version") || !strings.Contains(stdout, "  t a") {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if strings.Contains(stdout, "t hidden") {
		t.Fatalf("hidden command listed: %q", stdout)
	}
}
