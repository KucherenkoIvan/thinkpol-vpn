//go:build !linux || android

package agent

import (
	"fmt"
	"runtime"
)

// supported reports whether this OS can run a node's data plane. Nothing
// is configured before this check, so an unsupported host is left as it
// was (macOS's data plane is TP-019, Windows' TP-047, Android's runs in
// its VpnService).
func supported() error {
	return fmt.Errorf("%w: no data plane on %s yet", ErrUnsupported, runtime.GOOS)
}
