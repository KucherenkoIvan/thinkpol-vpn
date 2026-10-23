//go:build unix

package service

import (
	"io/fs"
	"os"
	"syscall"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// checkTrusted accepts dir if it and every directory above it are root's
// (or this user's) and writable by no one else (trusteddir).
func checkTrusted(dir string) error {
	d, err := trusteddir.Open(dir)
	if err != nil {
		return err
	}
	return d.Close()
}

// ownedSafely says whether fi is a regular file of this process's user
// (root's, for install) that neither its group nor others can write.
func ownedSafely(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode().IsRegular() && int(st.Uid) == os.Geteuid() && fi.Mode().Perm()&0o022 == 0
}
