//go:build !linux || android

package routetable

// No leak guard here yet (an Enforcer without one enforces routes only).
//
// TODO(TP-021, macOS): a pf anchor once TP-019's data plane is merged (see
// TP-021's Notes): the same GuardFor(w) rules, loaded into an anchor of
// our own, removed on Close and by Clear. Windows is TP-047/TP-048's;
// Android's VpnService takes every route.
func newGuard() Guard { return nil }

func clearGuard() error { return nil }
