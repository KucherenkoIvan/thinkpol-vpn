//go:build (!linux && !darwin) || android

package ifbind

import (
	"fmt"
	"runtime"
)

// bind fails: binding sockets to an interface isn't implemented here
// (Windows: TP-047), and Android needs none (VpnService protects sockets).
func bind(int, bool, Interface) error {
	return fmt.Errorf("ifbind: binding sockets to an interface is not implemented on %s", runtime.GOOS)
}
