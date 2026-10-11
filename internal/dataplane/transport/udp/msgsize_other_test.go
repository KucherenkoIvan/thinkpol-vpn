//go:build !windows

package udp

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

func TestWriteErrorMarksDatagramsTooLongForThePath(t *testing.T) {
	tooLong := &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EMSGSIZE)}
	if err := writeError(tooLong); !errors.Is(err, transport.ErrPacketTooLong) || !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("EMSGSIZE: %v", err)
	}
	other := &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.ECONNREFUSED)}
	if err := writeError(other); errors.Is(err, transport.ErrPacketTooLong) {
		t.Fatalf("ECONNREFUSED marked too long: %v", err)
	}
}
