//go:build unix

package lab

import (
	"errors"
	"os"
	"syscall"
)

// tryLockMode takes an advisory lock on path without waiting: exclusive,
// or shared (any number of holders at once, never together with an
// exclusive one). The kernel drops it when the process dies, so a killed
// run never leaves a stale lock.
func tryLockMode(path string, exclusive bool) (*os.File, bool, error) {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}
