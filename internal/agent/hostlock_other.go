//go:build !darwin

package agent

// hostLock takes nothing here yet. On Linux a second agent fails at
// netcfg's per-owner lock, but only after its start-time cleanups (the
// resolv.conf restore): a host-wide lock there is a follow-up (TP-019's
// Notes).
func hostLock() (func(), error) { return func() {}, nil }
