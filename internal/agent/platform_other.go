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
	return errNoDataPlane
}

// errNoDataPlane is a variable, not built in supported, so that
// staticcheck can't prove supported always fails here and flag the
// caller's error check.
var errNoDataPlane = fmt.Errorf("%w: no data plane on %s yet", ErrUnsupported, runtime.GOOS)
