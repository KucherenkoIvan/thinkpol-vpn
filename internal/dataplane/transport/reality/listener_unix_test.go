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

// slowReaderBound is the write timeout the slow-reader tests set. A
// writer to a Linux unix socket wakes only once its queued bytes fall to
// a quarter of the send buffer (4 KB set, 8 KB granted): at slowRead's
// 50 KB/s, about 165 ms between two writes that make progress.
const slowReaderBound = 600 * time.Millisecond

// slowRead reads from c about 1 KB every 20 ms, some 50 KB/s, for d, or
// for good with d 0, and returns the error that ended it, if any.
func slowRead(c net.Conn, d time.Duration) (read int, err error) {
	buf := make([]byte, 1<<10)
	for start := time.Now(); d == 0 || time.Since(start) < d; {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := io.ReadFull(c, buf)
		read += n
		if err != nil {
			return read, err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return read, nil
}

// One write to a reader that drains slowly but steadily ends once it is
// whole, however much longer than its timeout that takes, as nginx's
// send_timeout runs between two successive writes, not over a buffer.
func TestAWriteToASlowReaderOutlastsItsTimeoutWhileItProgresses(t *testing.T) {
	writer, reader := slowPair(t)
	go func() { _, _ = slowRead(reader, 0) }()
	w := &idleConn{Conn: writer, writeTimeout: slowReaderBound}
	p := make([]byte, 64<<10) // about 1.3 s to drain
	start := time.Now()
	if n, err := w.Write(p); err != nil || n != len(p) {
		t.Fatalf("a write to a slow reader ended after %v, %d of %d bytes: %v", time.Since(start).Round(time.Millisecond), n, len(p), err)
	}
}

// A stranger that reads slowly, but keeps reading, stays spliced; once it
// stops reading, the splice ends within spliceWriteTimeout, its slot
// freed.
func TestASlowReaderKeepsItsSpliceUntilItStopsReading(t *testing.T) {
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
		spliceJoined(clientEnd, target, time.Minute, slowReaderBound, nil, nil)
	}()
	if read, err := slowRead(client, 4*slowReaderBound); err != nil {
		t.Fatalf("a slow reader cut, %d bytes read: %v", read, err)
	}
	select {
	case <-done:
	case <-time.After(10 * slowReaderBound):
		t.Fatal("a reader that stopped still holds its splice")
	}
}
