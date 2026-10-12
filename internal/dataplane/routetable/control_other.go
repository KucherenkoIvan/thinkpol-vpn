//go:build (!linux && !darwin) || android

package routetable

import "syscall"

// SocketControl is nil where sockets aren't marked yet: Windows will bind
// them to the physical interface (TP-047), and Android's VpnService
// protects them.
func SocketControl() func(network, address string, c syscall.RawConn) error { return nil }
