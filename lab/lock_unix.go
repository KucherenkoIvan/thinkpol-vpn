//go:build unix

package lab

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive advisory lock on path without waiting. The
// kernel drops it when the process dies, so a killed run never leaves a
// stale lock.
func tryLock(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return f, true, nil
}
