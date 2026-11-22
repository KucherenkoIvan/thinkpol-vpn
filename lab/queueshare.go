package lab

import (
	"context"
	"fmt"
	"sync"
)

// slotQueueShare is how many of a process's slot waits stand in a lock
// directory's slot queue at once (0: no bound). The queue is first come
// first served, and make lab-test's lab/ phase runs every test at once:
// without a share, the starts it queues at once would all go before those
// of its node phase and of other runs. A share per process interleaves
// them as slots free up; a process's own waits take their turns among
// themselves.
var slotQueueShare = 2

var (
	queueSharesMu sync.Mutex
	queueShares   = map[string]chan struct{}{} // by lock directory
)

// slotQueueTurn waits for a place in this process's share of dir's slot
// queue (slotQueueShare), which leave gives back once the slot wait is
// over.
func slotQueueTurn(ctx context.Context, dir string) (leave func(), err error) {
	queueSharesMu.Lock()
	share, ok := queueShares[dir]
	if !ok && slotQueueShare > 0 {
		share = make(chan struct{}, slotQueueShare)
		queueShares[dir] = share
	}
	queueSharesMu.Unlock()
	if share == nil {
		return func() {}, nil
	}
	select {
	case share <- struct{}{}:
		return func() { <-share }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("lab: waiting for this process's turn in the slot queue: %w", ctx.Err())
	}
}
