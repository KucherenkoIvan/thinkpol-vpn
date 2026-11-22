//go:build darwin || linux

package safety

// running says pid is still the process that started at start and hasn't
// exited: a pid can be reused, and a zombie its parent hasn't reaped yet
// is gone.
func running(pid int, start int64) bool {
	return pid > 0 && sameProcess(pid, start) && !zombie(pid)
}

// sameProcess says pid is still the process that started at start.
func sameProcess(pid int, start int64) bool {
	got, err := startTime(pid)
	return err == nil && got == start
}
