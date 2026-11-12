//go:build unix

package reality

import (
	"errors"
	"net"
	"syscall"
)

// targetReset waits on c, whose FIN was read, until its peer resets it
// (true) or it is closed, times out or fails otherwise (false). Reading
// past a FIN returns at once, so it waits on the descriptor: a reset is
// a new event on it. Linux keeps reading EOF after the FIN even once
// reset, so the socket's pending error is what tells (EPIPE there, the
// reset coming in CLOSE_WAIT).
func targetReset(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var reset bool
	var b [1]byte
	_ = rc.Read(func(fd uintptr) bool {
		n, err := syscall.Read(int(fd), b[:])
		if err == nil && n == 0 {
			if e, gerr := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR); gerr == nil && e != 0 {
				err = syscall.Errno(e)
			}
		}
		switch {
		case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR), err == nil && n == 0:
			return false
		case err != nil:
			reset = isReset(err)
		}
		return true
	})
	return reset
}
