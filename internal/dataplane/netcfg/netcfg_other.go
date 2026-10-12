//go:build (!linux && !darwin) || android

package netcfg

import (
	"errors"
	"fmt"
	"runtime"
)

// New fails on OSes without an adapter yet (macOS: TP-019, Windows: TP-047),
// rather than half-configuring the host. On Android the VpnService builder
// sets addresses and routes, so there is never a netcfg adapter there.
func New(owner Owner) (Configurator, error) {
	return nil, fmt.Errorf("netcfg: no adapter for %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
