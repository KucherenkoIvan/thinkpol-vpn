//go:build unix

package reality

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"
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

// writeRearming writes p to c, each write(2) that makes progress
// re-arming c's write deadline to timeout from then, as nginx's
// send_timeout runs between two successive writes: a deadline set once
// for all of p would bound the time a slow reader takes to drain it,
// cutting one that keeps reading. Capping each write instead would be
// exact only below the share of the send buffer whose freeing wakes a
// writer (a third on Linux), and the kernel resizes that buffer as it
// goes. The poller still does the waiting, so c's Close ends it as it
// ends c.Write. A write is cancelled by closing c, not by a deadline: the
// next progress would overwrite it.
func writeRearming(c net.Conn, p []byte, timeout time.Duration) (int, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return writeRearmingByDeadline(c, p, timeout)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return writeRearmingByDeadline(c, p, timeout)
	}
	_ = c.SetWriteDeadline(time.Now().Add(timeout))
	written := 0
	var werr error
	err = rc.Write(func(fd uintptr) bool {
		for written < len(p) {
			n, err := syscall.Write(int(fd), p[written:])
			switch {
			case n > 0:
				written += n
				_ = c.SetWriteDeadline(time.Now().Add(timeout))
			case errors.Is(err, syscall.EINTR):
			case errors.Is(err, syscall.EAGAIN):
				return false
			case err != nil:
				werr = os.NewSyscallError("write", err)
				return true
			default:
				werr = io.ErrShortWrite
				return true
			}
		}
		return true
	})
	if werr == nil {
		werr = err
	}
	return written, werr
}
