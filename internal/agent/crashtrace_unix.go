//go:build unix

package agent

import (
	"fmt"
	"os"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

// fixCrashTraceFile makes the trace file f (fi its stat) the agent's
// user's (root, under the service) and 0600: launchd and systemd create it
// with their own umask, 0644 as a rule. It says what it changed.
func fixCrashTraceFile(f *os.File, fi os.FileInfo) (string, error) {
	var fixed string
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		if err := f.Chown(os.Geteuid(), os.Getegid()); err != nil {
			return "", fmt.Errorf("making it root's: %w", err)
		}
		fixed = fmt.Sprintf("owner uid %d made root's", st.Uid)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			return "", fmt.Errorf("making it 0600: %w", err)
		}
		if fixed != "" {
			fixed += ", "
		}
		fixed += fmt.Sprintf("mode %#o made 0600", perm)
	}
	return fixed, nil
}
