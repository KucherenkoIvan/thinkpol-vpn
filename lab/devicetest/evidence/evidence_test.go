package evidence

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAFolderPerRunNamedByDateAndTicket(t *testing.T) {
	base := filepath.Join(t.TempDir(), "thinkpol-evidence")
	now := time.Date(2026, 10, 23, 9, 0, 0, 0, time.Local)
	var term bytes.Buffer
	var paths []string
	for range 3 {
		f, err := Create(base, "TP-096", now, &term)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, filepath.Base(f.Path))
		_ = f.Close()
	}
	if strings.Join(paths, " ") != "2026-10-23-TP-096 2026-10-23-TP-096-2 2026-10-23-TP-096-3" {
		t.Errorf("folders %v", paths)
	}
	if fi, err := os.Stat(filepath.Join(base, paths[0])); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %v %v", fi, err)
	}
}

func TestNoEvidenceInAGitCheckout(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(filepath.Join(repo, "a", "evidence"), "TP-096", time.Now(), &bytes.Buffer{}); err == nil {
		t.Fatal("created inside a git checkout")
	}
	if _, err := os.Stat(filepath.Join(repo, "a")); !os.IsNotExist(err) {
		t.Errorf("made something there: %v", err)
	}
}

func TestOneTerminalWithTimestamps(t *testing.T) {
	var term bytes.Buffer
	f, err := Create(t.TempDir(), "TP-096", time.Now(), &term)
	if err != nil {
		t.Fatal(err)
	}
	f.Logf("step 1 stock")
	answer, err := f.Ask(bufio.NewReader(strings.NewReader("yes\n")), "Type yes:")
	if err != nil || answer != "yes" {
		t.Fatalf("answer %q %v", answer, err)
	}
	_ = f.Close()
	if !regexp.MustCompile(`(?m)^\d\d:\d\d:\d\d step 1 stock$`).Match(term.Bytes()) ||
		!regexp.MustCompile(`(?m)^\d\d:\d\d:\d\d Type yes: `).Match(term.Bytes()) {
		t.Errorf("terminal:\n%s", term.String())
	}
	log, _ := os.ReadFile(filepath.Join(f.Path, "harness.log"))
	if !regexp.MustCompile(`(?m)^\d{4}-\d\d-\d\dT\S+Z step 1 stock$`).Match(log) || !bytes.Contains(log, []byte(`answered: "yes"`)) {
		t.Errorf("harness.log:\n%s", log)
	}
	if notes, _ := os.ReadFile(filepath.Join(f.Path, "notes.md")); !bytes.Contains(notes, []byte(`Type yes:: "yes"`)) {
		t.Errorf("notes.md: %s", notes)
	}
	if err := f.WriteFile("../out", nil); err == nil {
		t.Error("wrote outside the folder")
	}
	if err := f.WriteFile("steps/01-stock/a.out", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile("steps/01-stock/a.out", []byte("y")); err == nil {
		t.Error("replaced a file")
	}
}
