//go:build !linux || android

package dns

// watchFile has no change notifications here: callers poll.
func watchFile(string) (<-chan struct{}, func()) { return nil, func() {} }
