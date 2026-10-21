package routetable

import (
	"context"
	"log/slog"
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

// OpenWithClock is OpenWithGuard with now as the warn rate limit's clock.
func OpenWithClock(c netcfg.Configurator, g Guard, log *slog.Logger, now func() time.Time) *Enforcer {
	return openWithClock(c, g, log, now)
}

// GuardApply is e's applyGuard.
func GuardApply(ctx context.Context, e *Enforcer, w Want) { e.applyGuard(ctx, w) }

// GuardWarnEvery is how far apart the guard's failures are warned.
const GuardWarnEvery = guardWarnEvery
