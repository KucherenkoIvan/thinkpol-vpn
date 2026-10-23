//go:build darwin || linux

package safety

import (
	"errors"

	"golang.org/x/sys/unix"
)

// alive says pid is a process that hasn't exited: a zombie its parent
// hasn't reaped yet is gone.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if err := unix.Kill(pid, 0); err != nil && !errors.Is(err, unix.EPERM) {
		return false
	}
	return !zombie(pid)
}

// sameProcess says pid is still the process that started at start (a pid
// can be reused).
func sameProcess(pid int, start int64) bool {
	got, err := startTime(pid)
	return err == nil && got == start
}
