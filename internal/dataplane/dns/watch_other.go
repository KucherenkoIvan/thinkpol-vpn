//go:build !linux || android

package dns

// watchFile has no change notifications here: callers poll.
func watchFile(string) (start func(own int) <-chan bool, closeWatch func()) {
	return func(int) <-chan bool { return nil }, func() {}
}
