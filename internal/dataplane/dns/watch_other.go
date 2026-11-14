//go:build !linux || android

package dns

// watchFile has no change notifications here: callers poll.
func watchFile(string) (start func() <-chan bool, closeWatch func()) {
	return func() <-chan bool { return nil }, func() {}
}
