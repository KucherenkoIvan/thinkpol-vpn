package routetable

import (
	"context"
	"time"
)

// ClearWith is Clear with the owner's configurator from open.
var ClearWith = clearWith

// GuardApply is applyGuard; the warn rate limit's test drives it.
func (e *Enforcer) GuardApply(ctx context.Context, w Want) { e.applyGuard(ctx, w) }

// SetNow replaces the enforcer's clock; the warn rate limit's test uses it.
func SetNow(e *Enforcer, now func() time.Time) { e.now = now }