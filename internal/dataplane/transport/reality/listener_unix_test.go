//go:build unix

package reality

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// slowPair is a connected pair of unix stream sockets with small
// buffers, the first to write to the slow reader, the second to read:
// unlike loopback TCP, whose windows the kernel sizes up whatever the
// socket's buffer, a writer to it waits as soon as the reader falls
// behind by a few kilobytes, and resumes as soon as it reads a few.
func slowPair(t *testing.T) (writer, reader net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) net.Conn {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4<<10)
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<10)
		f := os.NewFile(uintptr(fd), "slow")
		defer func() { _ = f.Close() }()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	return conn(fds[0]), conn(fds[1])
}

// A stranger that reads slowly, but keeps reading, stays spliced however
// long one write of the splice takes to drain, as nginx's send_timeout
// runs between two successive writes; once it stops reading, the splice
// ends within spliceWriteTimeout, its slot freed.
func TestASlowReaderKeepsItsSpliceUntilItStopsReading(t *testing.T) {
	const bound = 250 * time.Millisecond
	clientEnd, client := slowPair(t)
	target, site := tcpPair(t)
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := site.Write(chunk); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		spliceJoined(clientEnd, target, time.Minute, bound, nil, nil)
	}()
	// About 50 KB/s: a write of 32 KB takes 640 ms to drain.
	buf := make([]byte, 1<<10)
	read := 0
	for start := time.Now(); time.Since(start) < 8*bound; {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		n, err := io.ReadFull(client, buf)
		read += n
		if err != nil {
			t.Fatalf("a slow reader cut after %v, %d bytes read: %v", time.Since(start).Round(time.Millisecond), read, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(10 * bound):
		t.Fatal("a reader that stopped still holds its splice")
	}
}
