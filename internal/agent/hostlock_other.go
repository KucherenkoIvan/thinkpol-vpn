//go:build !linux && !darwin

package agent

// HostLock takes nothing here: no data plane on this OS yet (supported
// refuses before it is called).
func HostLock() (func(), error) { return func() {}, nil }
