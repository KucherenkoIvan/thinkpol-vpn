//go:build !windows

package udp

import (
	"errors"
	"syscall"
)

func isMessageSize(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }
