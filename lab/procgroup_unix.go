//go:build unix

package lab

import (
	"os/exec"
	"syscall"
)

// killGroupOnCancel starts cmd in a process group of its own and makes
// cancelling its context kill the whole group, not just cmd: go test's test
// binary is cmd's child and would otherwise outlive it, holding the output
// pipe until its own -test.timeout. A test binary has no signal handler, so
// no gentler signal would let its cleanups run.
func killGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
