//go:build linux && !android

package agent

// supported reports whether this OS can run a node's data plane in mode.
func supported(Mode) error { return nil }
