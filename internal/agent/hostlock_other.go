//go:build !linux && !darwin

package agent

// hostLock takes nothing here: no data plane on this OS yet (supported
// refuses before it is called).
func hostLock() (func(), error) { return func() {}, nil }
