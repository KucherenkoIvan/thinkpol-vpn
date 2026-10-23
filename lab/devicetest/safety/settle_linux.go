package safety

import "context"

// DefaultStateDir is root's directory for runs' journals.
const DefaultStateDir = "/var/lib/thinkpol-devicetest"

// rootCopyBase is where the root copy of the binary goes.
const rootCopyBase = "/tmp"

// settle has nothing to wait for on Linux: no plan runs an agent there.
func settle(context.Context, *Host) []string { return nil }
