//go:build linux && !android

package ifbind

import (
	"errors"

	"golang.org/x/sys/unix"
)

// bind sets SO_BINDTODEVICE, by name, for either family.
func bind(fd int, _ bool, ifc Interface) error {
	if ifc.Name == "" {
		return errors.New("ifbind: no interface name")
	}
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifc.Name)
}
