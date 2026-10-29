package trusteddir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A file macOS refuses to unlink (EPERM, here its owner's immutable flag)
// is reported with that error, not with the retry's as a directory
// (ENOTDIR), and stays.
func TestRemoveEntrySaysWhyAFileStays(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	file := filepath.Join(path, "file")
	if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(file, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(file, 0) })
	if err := RemoveEntry(d, "file"); !errors.Is(err, unix.EPERM) {
		t.Errorf("an immutable file: %v, want EPERM", err)
	}
	if _, err := os.Lstat(file); err != nil {
		t.Errorf("the file: %v", err)
	}
}
