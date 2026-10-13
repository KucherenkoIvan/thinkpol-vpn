package dns

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isMessageSize reports a datagram too big for the read buffer: Windows
// fails the read (WSAEMSGSIZE) where other systems truncate it quietly.
func isMessageSize(err error) bool { return errors.Is(err, windows.WSAEMSGSIZE) }
