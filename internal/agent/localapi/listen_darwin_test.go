package localapi

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// The default socket's directory is made in a parent Listen accepts when
// the service runs as root: root's and writable by no one else, unlike
// /private/var/run (root:daemon 0775). Read-only.
func TestTheDefaultSocketsParentPassesTheParentCheck(t *testing.T) {
	parent := filepath.Dir(filepath.Dir(agent.DefaultAPISocket()))
	if err := checkParent(parent); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != os.ModeDir || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("%s: %v, want a directory of root's, not a symlink", parent, fi.Mode())
	}
	if err := checkParent("/private/var/run"); err == nil {
		t.Error("/private/var/run passes the parent check")
	}
}
