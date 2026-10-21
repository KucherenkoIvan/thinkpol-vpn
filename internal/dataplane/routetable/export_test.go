package routetable

import (
	"context"
	"log/slog"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// ClearWith is Clear with the owner's configurator from open.
func ClearWith(open func() (netcfg.Configurator, error), g Guard) error { return clearWith(open, g) }

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

// WarnEvery is how far apart a failure's warns are.
const WarnEvery = warnEvery

// WarnTexts is how many distinct failures one site warns a window.
const WarnTexts = warnTexts

// PauseWatching stops e's watcher, so a test drives its steps alone.
func PauseWatching(e *Enforcer) { e.pauseWatching() }

// Subscribe is e's subscribe to the routes' changes.
func Subscribe(ctx context.Context, e *Enforcer) { e.subscribe(ctx, &watches{}) }

// SubscribeGuard is e's subscribe to the guard's changes.
func SubscribeGuard(ctx context.Context, e *Enforcer) { e.subscribeGuard(ctx, &watches{}) }

// Reapply is e's re-apply of the last Want.
func Reapply(ctx context.Context, e *Enforcer) { e.reapply(ctx) }
