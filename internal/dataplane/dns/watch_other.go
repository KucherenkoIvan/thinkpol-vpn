//go:build !linux || android

package dns

// watchFile has no change notifications here: callers poll.
func watchFile(string) (<-chan bool, func()) { return nil, func() {} }
