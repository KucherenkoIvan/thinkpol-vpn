package safety

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// statFields are /proc/<pid>/stat's fields after the name: the state
// first.
func statFields(pid int) ([]string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	// The name in parentheses may hold spaces: fields count from its end.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return nil, fmt.Errorf("/proc/%d/stat: no name", pid)
	}
	return strings.Fields(string(b[i+1:])), nil
}

// zombie says pid has exited and waits to be reaped.
func zombie(pid int) bool {
	f, err := statFields(pid)
	return err == nil && len(f) > 0 && f[0] == "Z"
}

// startTime is when pid started (clock ticks after boot, field 22 of
// /proc/<pid>/stat).
func startTime(pid int) (int64, error) {
	f, err := statFields(pid)
	if err != nil {
		return 0, err
	}
	if len(f) < 20 {
		return 0, fmt.Errorf("/proc/%d/stat: %d fields", pid, len(f))
	}
	return strconv.ParseInt(f[19], 10, 64)
}
