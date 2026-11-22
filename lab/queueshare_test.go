//go:build unix

package lab

import (
	"context"
	"testing"
	"time"
)

// TestAProcessStandsAtMostItsShareInTheSlotQueue: a process stands no
// more than its share of slot waits in the slot queue at once; the next
// joins as one of them leaves it (with the slot).
func TestAProcessStandsAtMostItsShareInTheSlotQueue(t *testing.T) {
	dir := oneSlotHost(t)
	queueShareOf(t, 2)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	held := holdSlot(t, ctx)
	got := make(chan func(), 3)
	for range 3 {
		go func() {
			release, err := acquireHostSlot(ctx)
			if err != nil {
				t.Error(err)
			}
			got <- release
		}()
	}
	waitForTickets(t, dir, 2)
	// Nothing to watch: the third wait does nothing while it is held back.
	time.Sleep(300 * time.Millisecond)
	if tickets := queueTickets(t, dir); len(tickets) != 2 {
		t.Fatalf("the slot queue holds %v: want the process's share, 2", tickets)
	}
	held()
	for range 3 {
		if release := <-got; release != nil {
			release()
		}
	}
}
