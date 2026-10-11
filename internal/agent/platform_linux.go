//go:build linux && !android

package agent

// supported reports whether this OS can run a node's data plane.
func supported() error { return nil }
