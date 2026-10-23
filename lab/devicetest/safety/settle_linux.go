package safety

import "context"

// settle has nothing to wait for on Linux: no plan runs an agent there.
func settle(context.Context, *host) []string { return nil }
