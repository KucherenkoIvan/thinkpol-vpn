package path

import "time"

// WatchEvery sets how often a node checks its links, on the wall clock:
// tests with a fake clock check often and step the clock in small steps.
func WatchEvery(o Options, d time.Duration) Options {
	o.watchEvery = d
	return o
}
