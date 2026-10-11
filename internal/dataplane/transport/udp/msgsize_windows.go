package udp

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isMessageSize(err error) bool { return errors.Is(err, windows.WSAEMSGSIZE) }
