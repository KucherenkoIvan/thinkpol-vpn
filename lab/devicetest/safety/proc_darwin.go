package safety

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// startTime is when pid started (microseconds since the epoch), the
// kernel's own record of it.
func startTime(pid int) (int64, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if int(kp.Proc.P_pid) != pid {
		return 0, unix.ESRCH
	}
	return kp.Proc.P_starttime.Sec*1_000_000 + int64(kp.Proc.P_starttime.Usec), nil
}

// processesNamed are the pids of processes whose name (the kernel's
// p_comm) is name.
func processesNamed(name string) ([]int, error) {
	all, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	var out []int
	for _, kp := range all {
		comm := kp.Proc.P_comm[:]
		if i := bytes.IndexByte(comm, 0); i >= 0 {
			comm = comm[:i]
		}
		if string(comm) == name {
			out = append(out, int(kp.Proc.P_pid))
		}
	}
	return out, nil
}

// zombie says pid has exited and waits to be reaped (SZOMB).
func zombie(pid int) bool {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && int(kp.Proc.P_pid) == pid && kp.Proc.P_stat == 5
}
