package ifbind

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bind sets IP_BOUND_IF or IPV6_BOUND_IF, by index: the socket then routes
// by the interface's scoped routes only (its own subnet and default
// route), never by an unscoped route to another interface such as the
// utun's split routes.
func bind(fd int, ipv6 bool, ifc Interface) error {
	index := ifc.Index
	if index == 0 {
		if ifc.Name == "" {
			return errors.New("ifbind: no interface")
		}
		i, err := net.InterfaceByName(ifc.Name)
		if err != nil {
			return fmt.Errorf("ifbind: %w", err)
		}
		index = i.Index
	}
	if ipv6 {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
}
