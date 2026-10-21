package routetable

import (
	"context"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// ClearWith is Clear with the owner's configurator from open.
var ClearWith = clearWith

// Config is LayoutOf's Config.
func Config(w Want, s netcfg.Survey) netcfg.Config { return LayoutOf(w, s).Config }

// Ahead is LayoutOf's Ahead.
func Ahead(w Want, s netcfg.Survey) int { return LayoutOf(w, s).Ahead }

// OverlayAhead is LayoutOf's OverlayAhead.
func OverlayAhead(w Want, s netcfg.Survey) int { return LayoutOf(w, s).OverlayAhead }

// GuardApply is applyGuard; the warn rate limit's test drives it.
func (e *Enforcer) GuardApply(ctx context.Context, w Want) { e.applyGuard(ctx, w) }

// SetNow replaces the enforcer's clock; the warn rate limit's test uses it.
func SetNow(e *Enforcer, now func() time.Time) { e.now = now }
