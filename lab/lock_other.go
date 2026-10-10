//go:build !unix

package lab

import "os"

// tryLock always succeeds: the lab runs on unix hosts only, this just keeps
// the package building everywhere.
func tryLock(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	return f, err == nil, err
}
