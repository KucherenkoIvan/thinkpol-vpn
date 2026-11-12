//go:build !unix

package reality

import "net"

// targetReset doesn't watch: a reset of the target reaches the client
// once a write to the target fails on it.
func targetReset(net.Conn) bool { return false }
