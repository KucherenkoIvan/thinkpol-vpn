//go:build !unix

package reality

import (
	"net"
	"time"
)

// targetReset doesn't watch: a reset of the target reaches the client
// once a write to the target fails on it.
func targetReset(net.Conn) bool { return false }

// writeRearming writes p to c, re-arming its write deadline to timeout
// whenever a write timed out having made progress.
func writeRearming(c net.Conn, p []byte, timeout time.Duration) (int, error) {
	return writeRearmingByDeadline(c, p, timeout)
}
