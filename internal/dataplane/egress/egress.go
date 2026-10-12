package egress

import "errors"

// Uplink is the interface a node's internet traffic leaves by.
type Uplink struct {
	// Name is the interface's name in the root namespace.
	Name string
	// IPv4 and IPv6 say which families reach the internet through it: a
	// default route of that family leaves by it, and for IPv6 it has an
	// address beyond link-local, which NAT66 masquerades to.
	IPv4, IPv6 bool
}

// ErrNoUplink means the node has no default route: no internet to egress to.
var ErrNoUplink = errors.New("egress: no default route")

// ErrUnsupported is returned where egress isn't implemented: everywhere but
// desktop Linux.
var ErrUnsupported = errors.New("egress: needs Linux")
