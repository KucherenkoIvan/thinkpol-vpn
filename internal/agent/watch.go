package agent

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// mapWatcher notices a new map: the file at path changed (checked every
// interval: replaced, resized or touched), or reload fired (SIGHUP). The
// map is all a node takes; it never asks a controller (DESIGN.md rule 2).
type mapWatcher struct {
	path     string
	interval time.Duration
	reload   <-chan os.Signal
	log      *slog.Logger
	// last is the file as last read.
	last os.FileInfo
}

// run delivers the file's contents to out (latest-wins: a pending one not
// yet taken is replaced) until ctx ends. Whether they are a newer map is
// for the receiver to decide.
func (w *mapWatcher) run(ctx context.Context, out chan []byte) error {
	tick := time.NewTicker(w.interval)
	defer tick.Stop()
	var lastErr string
	for {
		forced := false
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		case <-w.reload:
			forced = true
			w.log.Info("reload requested", "map", w.path)
		}
		if !forced {
			changed, err := mapChanged(w.last, w.path)
			if err != nil {
				// A map being replaced by hand can be missing for a moment.
				if err.Error() != lastErr {
					w.log.Warn("checking the map file", "err", err)
					lastErr = err.Error()
				}
				continue
			}
			if !changed {
				continue
			}
		}
		envelope, fi, err := readMap(w.path)
		if err != nil {
			w.log.Warn("reading the map file", "err", err)
			lastErr = err.Error()
			continue
		}
		lastErr = ""
		w.last = fi
		select {
		case <-out:
		default:
		}
		out <- envelope
	}
}
