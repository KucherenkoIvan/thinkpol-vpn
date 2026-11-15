// Package trusteddirtest gives tests directories that trusteddir accepts.
package trusteddirtest

import (
	"os"
	"path/filepath"
	"testing"
)

// TempDir is t.TempDir by its real path, mode 0755 whatever the umask.
// trusteddir refuses a path through a symlink (macOS's temporary
// directories are under /var, one) and a group- or world-writable
// directory, and t.TempDir's is 0777 less the umask.
func TempDir(t testing.TB) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}
