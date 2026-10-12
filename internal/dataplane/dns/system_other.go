//go:build !linux || android

package dns

import (
	"fmt"
	"net/netip"
	"runtime"
)

// SetSystem points the OS resolver at the node's resolver; not on this
// platform yet (macOS: TP-019).
func SetSystem(SystemConfig) (System, error) {
	return nil, fmt.Errorf("dns: system resolver configuration not on %s yet", runtime.GOOS)
}

// RestoreSystem has nothing to restore here.
func RestoreSystem() error { return nil }

// SystemUpstreams are the resolvers the OS uses on its own; not known on
// this platform yet.
func SystemUpstreams([]netip.Addr) ([]netip.Addr, error) {
	return nil, fmt.Errorf("dns: system resolvers not known on %s yet", runtime.GOOS)
}
