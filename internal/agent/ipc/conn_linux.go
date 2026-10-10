//go:build linux

package ipc

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

// Conn is one end of a supervisor–worker socket. Send is safe for
// concurrent use; Receive is for one reader at a time.
type Conn struct {
	c *net.UnixConn

	rmu sync.Mutex
	buf []byte
	oob []byte
}

// Pair returns a new socket pair: the supervisor's Conn, and the worker's
// end as a file to pass to the worker (exec.Cmd.ExtraFiles, so it lands at
// WorkerFD). The caller closes the file once the worker has it.
func Pair() (*Conn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("ipc: socketpair: %w", err)
	}
	local := os.NewFile(uintptr(fds[0]), "ipc-supervisor")
	remote := os.NewFile(uintptr(fds[1]), "ipc-worker")
	c, err := FromFile(local)
	_ = local.Close()
	if err != nil {
		_ = remote.Close()
		return nil, nil, err
	}
	return c, remote, nil
}

// FromFile makes a Conn of a SOCK_SEQPACKET Unix socket, e.g. the worker's
// inherited WorkerFD. It duplicates the descriptor; the caller closes f.
func FromFile(f *os.File) (*Conn, error) {
	typ, err := unix.GetsockoptInt(int(f.Fd()), unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return nil, fmt.Errorf("ipc: %s is not a socket: %w", f.Name(), err)
	}
	if typ != unix.SOCK_SEQPACKET {
		return nil, fmt.Errorf("ipc: %s is not a SOCK_SEQPACKET socket", f.Name())
	}
	nc, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		_ = nc.Close()
		return nil, fmt.Errorf("ipc: %s is not a Unix socket", f.Name())
	}
	return &Conn{
		c:   uc,
		buf: make([]byte, MaxMessageSize+1), // +1 tells a full message from a truncated one
		oob: make([]byte, unix.CmsgSpace(4*MaxFiles)),
	}, nil
}

// Send sends m as one packet.
func (c *Conn) Send(m Message) error {
	if 1+len(m.Payload) > MaxMessageSize {
		return fmt.Errorf("ipc: %v message of %d bytes is over %d", m.Kind, 1+len(m.Payload), MaxMessageSize)
	}
	if len(m.Files) > MaxFiles {
		return fmt.Errorf("ipc: %d files attached, at most %d", len(m.Files), MaxFiles)
	}
	b := make([]byte, 1+len(m.Payload))
	b[0] = byte(m.Kind)
	copy(b[1:], m.Payload)
	var oob []byte
	if len(m.Files) > 0 {
		fds := make([]int, len(m.Files))
		for i, f := range m.Files {
			fds[i] = int(f.Fd())
		}
		oob = unix.UnixRights(fds...)
	}
	_, _, err := c.c.WriteMsgUnix(b, oob, nil)
	runtime.KeepAlive(m.Files)
	if err != nil {
		return fmt.Errorf("ipc: send %v: %w", m.Kind, err)
	}
	return nil
}

// Receive blocks for the next message. io.EOF means the other end is gone.
func (c *Conn) Receive() (Message, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	// The kernel sets close-on-exec on received descriptors
	// (MSG_CMSG_CLOEXEC, which the net package passes on Linux).
	n, oobn, flags, _, err := c.c.ReadMsgUnix(c.buf, c.oob)
	files, ferr := parseRights(c.oob[:oobn])
	m := Message{Files: files}
	switch {
	case err != nil:
		m.CloseFiles()
		if errors.Is(err, io.EOF) {
			return Message{}, io.EOF
		}
		return Message{}, fmt.Errorf("ipc: receive: %w", err)
	case ferr != nil:
		m.CloseFiles()
		return Message{}, ferr
	case n == 0:
		// Every message has a kind byte, so an empty read is the end.
		m.CloseFiles()
		return Message{}, io.EOF
	case flags&unix.MSG_TRUNC != 0 || n > MaxMessageSize:
		m.CloseFiles()
		return Message{}, fmt.Errorf("ipc: message over %d bytes", MaxMessageSize)
	case flags&unix.MSG_CTRUNC != 0:
		m.CloseFiles()
		return Message{}, fmt.Errorf("ipc: more than %d files attached", MaxFiles)
	}
	m.Kind = Kind(c.buf[0])
	m.Payload = append([]byte(nil), c.buf[1:n]...)
	return m, nil
}

func parseRights(oob []byte) ([]*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("ipc: control message: %w", err)
	}
	var files []*os.File
	var bad error
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			bad = fmt.Errorf("ipc: unexpected control message: %w", err)
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "ipc-received"))
		}
	}
	return files, bad
}

// Close closes the socket; a Receive blocked on it returns an error, and
// the other end sees EOF.
func (c *Conn) Close() error { return c.c.Close() }
