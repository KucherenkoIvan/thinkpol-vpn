package agent

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// Every directory the agent opens or makes at start by default passes the
// trusted walk it makes as root: /var, /etc and /tmp are symlinks to
// /private/..., which the walk refuses. Read-only: what exists of each
// path is opened, nothing is made.
func TestTheDefaultPathsPassTheTrustedWalk(t *testing.T) {
	for _, path := range []string{DefaultStateDir, filepath.Dir(hostLockPath), netcfg.LockDir, filepath.Dir(DefaultAPISocket())} {
		if err := walkExisting(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	if err := walkExisting("/var/lib/thinkpol"); err == nil {
		t.Error("/var/lib/thinkpol passes the walk through the /var symlink")
	}
}

// walkExisting opens path and each of its ancestors with trusteddir.Open,
// from / down to the first one missing or closed to this unprivileged
// user, and requires each to be root's, as the walk does when the agent
// runs as root.
func walkExisting(path string) error {
	walked := "/"
	for _, c := range append([]string{""}, strings.Split(strings.TrimPrefix(path, "/"), "/")...) {
		walked = filepath.Join(walked, c)
		d, err := trusteddir.Open(walked)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil
		}
		if err != nil {
			return err
		}
		fi, err := d.Stat()
		_ = d.Close()
		if err != nil {
			return err
		}
		if uid := fi.Sys().(*syscall.Stat_t).Uid; uid != 0 {
			return errors.New(walked + ": not root's")
		}
	}
	return nil
}
