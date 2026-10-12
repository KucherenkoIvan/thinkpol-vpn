//go:build !linux || android

package egress

// FindUplink fails where there is no egress.
func FindUplink() (Uplink, error) { return Uplink{}, ErrUnsupported }
