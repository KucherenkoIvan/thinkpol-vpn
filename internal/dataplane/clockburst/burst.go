package clockburst

import (
	"sync"
	"time"
)

// Window is how many stale-clock drops fell in the current reporting window.
type Window struct {
	mu    sync.Mutex
	start time.Time
	count uint64
	width time.Duration
}

// NewWindow returns a counter that resets after width without a drop.
func NewWindow(width time.Duration) *Window {
	return &Window{width: width}
}

// Add records n drops at now.
func (w *Window) Add(n uint64, now time.Time) {
	if n == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count == 0 || now.Sub(w.start) > w.width {
		w.start = now
		w.count = n
		return
	}
	w.count += n
}

// Count is how many drops are in the window at now (0 when the window expired).
func (w *Window) Count(now time.Time) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.count == 0 || now.Sub(w.start) > w.width {
		return 0
	}
	return w.count
}
