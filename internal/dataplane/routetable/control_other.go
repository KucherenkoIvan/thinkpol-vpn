//go:build !linux || android

package routetable

import "syscall"

// SocketControl is nil where sockets aren't marked yet: macOS binds them to
// the physical interface (TP-019), Windows likewise (TP-047), and Android's
// VpnService protects them.
func SocketControl() func(network, address string, c syscall.RawConn) error { return nil }
