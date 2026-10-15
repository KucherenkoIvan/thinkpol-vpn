package dataplane

import (
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/clockburst"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

func TestEngineStaleClockBurstFromListeners(t *testing.T) {
	var n uint64
	e := &Engine{
		staleClockBurst: clockburst.NewWindow(5 * time.Minute),
		staleClockers: []staleClockFeed{{
			id:    1,
			count: func() uint64 { return n },
			at:    func() time.Time { return time.Unix(1_800_000_000, 0) },
		}},
	}
	n = 4
	e.mu.Lock()
	listeners := uint64(0)
	var listenerAt time.Time
	for _, f := range e.staleClockers {
		listeners += f.count()
		if f.at != nil {
			if t := f.at(); t.After(listenerAt) {
				listenerAt = t
			}
		}
	}
	now := time.Now()
	if listeners > e.staleClockFolded {
		e.staleClockBurst.Add(listeners-e.staleClockFolded, now)
		e.staleClockFolded = listeners
		e.staleClockSeenAt = listenerAt
	}
	burst := e.staleClockBurst.Count(now)
	e.mu.Unlock()
	if listeners != 4 || burst != 4 || e.staleClockSeenAt.Unix() != 1_800_000_000 {
		t.Fatalf("listeners %d burst %d seen %v", listeners, burst, e.staleClockSeenAt)
	}
}

func TestEngineUnregistersStaleClocker(t *testing.T) {
	feed := staleClockFeed{id: 1, count: func() uint64 { return 0 }}
	e := &Engine{staleClockBurst: clockburst.NewWindow(5 * time.Minute), staleClockers: []staleClockFeed{feed}}
	e.mu.Lock()
	for i, f := range e.staleClockers {
		if f.id == feed.id {
			e.staleClockers = append(e.staleClockers[:i], e.staleClockers[i+1:]...)
			break
		}
	}
	e.mu.Unlock()
	if len(e.staleClockers) != 0 {
		t.Fatal("feeder remained")
	}
}

// compile-time check that Serve still matches transport.Listener.
var _ = func(e *Engine, l transport.Listener) { _ = e.Serve("", l) }
