//go:build unix

package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// The blob store follows the state directory's rules: its files are
// private, and nothing behind a symlink or in a directory others can
// write is read or written.
func TestDiskBlobsFollowTheStateDirectorysRules(t *testing.T) {
	s := newTestSpace(t)
	ru, ref := s.withList(t, "ru", "192.0.2.0/24")
	dir := s.stateDir(t, s.b, 1)
	d := diskBlobs{dir: dir, log: slog.New(slog.DiscardHandler)}
	if err := d.Save(ref, ru); err != nil {
		t.Fatal(err)
	}
	bd := filepath.Join(dir, BlobDir)
	file := filepath.Join(bd, blobFileName(ref.SHA256))
	for path, want := range map[string]os.FileMode{bd: 0o700, file: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&^want != 0 {
			t.Errorf("%s: mode %v, want at most %v", path, fi.Mode().Perm(), want)
		}
	}

	// A symlink in place of the blob is not followed.
	elsewhere := filepath.Join(tempDir(t), "ru")
	writeFile(t, elsewhere, ru, 0o600)
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, file); err != nil {
		t.Fatal(err)
	}
	if got := d.Load(ref); got != nil {
		t.Error("loaded a blob through a symlink")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}

	// A directory others can write is neither read nor written.
	writeFile(t, file, ru, 0o600)
	if err := os.Chmod(bd, 0o777); err != nil {
		t.Fatal(err)
	}
	if got := d.Load(ref); got != nil {
		t.Error("loaded a blob from a directory others can write")
	}
	if err := d.Save(ref, ru); err == nil {
		t.Error("saved a blob into a directory others can write")
	}
}
