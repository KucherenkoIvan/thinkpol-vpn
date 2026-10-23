//go:build darwin || linux

package safety

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheEvidenceWriterNeverFollowsASymlink(t *testing.T) {
	base := tempDir(t)
	folder, elsewhere := filepath.Join(base, "evidence"), filepath.Join(base, "elsewhere")
	for _, d := range []string{folder, elsewhere} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	victim := filepath.Join(elsewhere, "victim")
	writeFile(t, victim, "keep")
	if err := os.Symlink(elsewhere, filepath.Join(folder, "captures")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(folder, "a.out")); err != nil {
		t.Fatal(err)
	}
	ev, err := openEvidence(folder, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ev.dir.Close() }()
	for _, rel := range []string{"captures/en0.pcap", "a.out", "../x", "/abs", "a/../b", "", "steps//x"} {
		if err := ev.writeFile(rel, []byte("written")); err == nil {
			t.Errorf("%q was written", rel)
		}
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("written through a symlink: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "en0.pcap")); err == nil {
		t.Error("a file was made through a symlinked directory")
	}
	if err := ev.writeFile("steps/01-stock/cmd-001.out", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := ev.writeFile("steps/01-stock/cmd-001.out", []byte("y")); err == nil {
		t.Error("an existing file was replaced")
	}
	if b, _ := os.ReadFile(filepath.Join(folder, "steps/01-stock/cmd-001.out")); string(b) != "x" {
		t.Errorf("content %q", b)
	}
}

func TestTheEvidenceFolderMustBeTheUsers(t *testing.T) {
	base := tempDir(t)
	folder := filepath.Join(base, "evidence")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(folder, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := openEvidence(filepath.Join(base, "link"), os.Getuid(), os.Getgid()); err == nil {
		t.Error("opened through a symlink")
	}
	if _, err := openEvidence(folder, os.Getuid()+4321, os.Getgid()); err == nil {
		t.Error("opened as another user's")
	}
	if os.Getuid() != 0 {
		if _, err := openEvidence("/usr", os.Getuid(), os.Getgid()); err == nil {
			t.Error("a directory of root's was taken for the user's folder")
		}
	}
}
