package localapi

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// callerOf reads the credentials of c's peer (LOCAL_PEERCRED): its uid and
// its groups, the effective one first, as they were when it connected.
func callerOf(c syscall.Conn) (Caller, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Caller{}, err
	}
	var caller Caller
	var opErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			opErr = err
			return
		}
		n := min(int(cred.Ngroups), len(cred.Groups))
		caller = Caller{UID: cred.Uid, GIDs: append([]uint32(nil), cred.Groups[:n]...)}
	})
	if err != nil {
		return Caller{}, err
	}
	return caller, opErr
}
