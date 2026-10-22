//go:build unix

package service

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"

// checkTrusted accepts dir if it and every directory above it are root's
// (or this user's) and writable by no one else (trusteddir).
func checkTrusted(dir string) error {
	d, err := trusteddir.Open(dir)
	if err != nil {
		return err
	}
	return d.Close()
}
