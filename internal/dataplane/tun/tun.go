package tun

import "errors"

// ErrUnsupported is returned where creating a TUN isn't implemented yet.
var ErrUnsupported = errors.New("tun: not supported on this OS yet")

// DefaultName is the overlay interface's name where the OS lets us choose.
const DefaultName = "thinkpol0"
