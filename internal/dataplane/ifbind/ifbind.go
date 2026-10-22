package ifbind

import (
	"errors"
	"syscall"
)

// Interface is the interface a socket is bound to. Linux needs its name;
// macOS its index, looked up by name when Index is zero.
type Interface struct {
	Name  string
	Index int
}

// Control is a socket Control (net.Dialer.Control, net.ListenConfig.Control)
// that binds each socket to the interface pick returns for it; pick is
// called per socket, with whether the socket is IPv6, so a binding can
// follow an interface that changes (the physical one, when the network
// changes). A socket pick or the OS can't bind fails to open.
func Control(pick func(ipv6 bool) (Interface, error)) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		ipv6, err := isIPv6(network)
		if err != nil {
			return err
		}
		ifc, err := pick(ipv6)
		if err != nil {
			return err
		}
		var serr error
		if err := c.Control(func(fd uintptr) { serr = bind(int(fd), ipv6, ifc) }); err != nil {
			return err
		}
		return serr
	}
}

// ByName is Control for one named interface.
func ByName(name string) func(network, address string, c syscall.RawConn) error {
	return Control(func(bool) (Interface, error) { return Interface{Name: name}, nil })
}

// isIPv6 tells the socket's family from the network the net package
// passes to a Control: "tcp4", "udp6" and so on, never "tcp" or "udp".
func isIPv6(network string) (bool, error) {
	if network == "" {
		return false, errors.New("ifbind: no network")
	}
	switch network[len(network)-1] {
	case '4':
		return false, nil
	case '6':
		return true, nil
	}
	return false, errors.New("ifbind: network " + network + " has no address family")
}
