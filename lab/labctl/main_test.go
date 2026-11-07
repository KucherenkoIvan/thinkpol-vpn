package main

import (
	"os"
	"path/filepath"
	"testing"
)

// labctl down -run with an empty or invalid id (-run "$THINKPOL_LAB_RUN",
// the variable unset) fails before asking Docker anything, instead of
// becoming a plain down that removes every lab of the checkout.
func TestDownRunRejectsABadIDBeforeDocker(t *testing.T) {
	called := fakeDockerMarker(t)
	root := t.TempDir()

	for _, id := range []string{"", "Bad-ID", "r1-x", "123456789"} {
		if err := down(t.Context(), root, []string{"-run", id}); err == nil {
			t.Errorf("down -run %q: no error", id)
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatalf("down -run %q asked Docker", id)
		}
	}
}

// labctl down with a positional argument (down r1 -run r1, or down r1 with
// -run forgotten) fails before asking Docker anything: flag parsing stops at
// the argument, so -run would go unseen and the whole checkout's labs go.
func TestDownRejectsPositionalArgumentsBeforeDocker(t *testing.T) {
	called := fakeDockerMarker(t)
	root := t.TempDir()

	for _, args := range [][]string{{"r1"}, {"r1", "-run", "r1"}, {"-tests", "r1"}} {
		if err := down(t.Context(), root, args); err == nil {
			t.Errorf("down %q: no error", args)
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatalf("down %q asked Docker", args)
		}
	}
}

// fakeDockerMarker puts a failing docker on PATH that creates the file it
// returns when called.
func fakeDockerMarker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	script := "#!/bin/sh\ntouch '" + called + "'\necho fake docker >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return called
}
