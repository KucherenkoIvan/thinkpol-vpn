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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	ok, err := tryLockFile(f, exclusive)
	if !ok {
		_ = f.Close()
		return nil, false, err
	}
	return f, true, nil
}

// tryLockFile is tryLockMode on a file already open. The lock belongs to
// this open file: another open of the same path, even in this process,
// doesn't hold it.
func tryLockFile(f *os.File, exclusive bool) (bool, error) {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
