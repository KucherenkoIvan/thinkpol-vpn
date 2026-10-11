package localapi

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// callerOf reads the credentials of c's peer: its uid and effective gid
// (SO_PEERCRED) and its supplementary groups (SO_PEERGROUPS), as they were
// when it connected.
func callerOf(c *net.UnixConn) (Caller, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Caller{}, err
	}
	var caller Caller
	var opErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			opErr = err
			return
		}
		groups, err := peerGroups(int(fd))
		if err != nil {
			opErr = err
			return
		}
		caller = Caller{UID: cred.Uid, GIDs: append([]uint32{cred.Gid}, groups...)}
	})
	if err != nil {
		return Caller{}, err
	}
	return caller, opErr
}

// peerGroups is SO_PEERGROUPS, which x/sys has no helper for: the buffer
// grows to the size the kernel asks for.
func peerGroups(fd int) ([]uint32, error) {
	buf := make([]uint32, 32)
	for {
		size := uint32(len(buf) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch {
		case errno == unix.ERANGE && int(size/4) > len(buf):
			buf = make([]uint32, size/4)
			continue
		case errno != 0:
			return nil, errno
		}
		return buf[:size/4], nil
	}
}
