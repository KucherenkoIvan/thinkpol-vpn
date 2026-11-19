package lab

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSlotWaitsBehindFirstStarts: a lab start's slot wait doesn't join
// the slot queue while a first start counted in for the same lock
// directory hasn't joined it yet, so the first start gets the slot ahead
// of it; once that one joined, it queues behind; a wait in another lock
// directory goes on; and a first wave that never began fails the wait
// after the grace rather than holding it forever.
func TestSlotWaitsBehindFirstStarts(t *testing.T) {
	// Its own lock directory: the lab tests' first starts, if any, are
	// another's.
	dir := oneSlotHost(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	launch, joined := firstStarts.hold(dir)
	other := make(chan error, 1)
	var otherRelease func()
	go func() {
		release, err := acquireHostSlot(ctx)
		otherRelease = release
		other <- err
	}()
	launch()
	// Nothing to watch: the other wait does nothing while it is held back.
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-other:
		t.Fatalf("the other slot wait ended ahead of the first start: %v", err)
	default:
	}
	if tickets := queueTickets(t, dir); len(tickets) != 0 {
		t.Fatalf("the other slot wait joined the queue ahead of the first start: %v", tickets)
	}
	firstRelease, err := acquireHostSlot(asFirstStart(ctx, joined))
	if err != nil {
		t.Fatal(err)
	}
	waitForTickets(t, dir, 1) // the other one, behind the held slot
	select {
	case err := <-other:
		t.Fatalf("the other slot wait ended while the first start held the only slot: %v", err)
	default:
	}
	firstRelease()
	if err := <-other; err != nil {
		t.Fatal(err)
	}
	otherRelease()

	// Another lock directory's first starts hold nobody here up.
	firstStarts.hold(t.TempDir())
	release, err := acquireHostSlot(ctx)
	if err != nil {
		t.Fatalf("a first start of another lock directory held the wait up: %v", err)
	}
	release()

	savedGrace := firstLaunchGrace
	firstLaunchGrace = 50 * time.Millisecond
	t.Cleanup(func() { firstLaunchGrace = savedGrace })
	firstStarts.hold(dir) // never launched: its test never resumed
	if _, err := acquireHostSlot(ctx); err == nil || !strings.Contains(err.Error(), "must call t.Parallel first") {
		t.Fatalf("behind first starts that never began: %v", err)
	}
	short, cancelShort := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelShort()
	launch, _ = firstStarts.hold(dir)
	launch()
	if _, err := acquireHostSlot(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("behind first starts past its deadline: %v", err)
	}
}
