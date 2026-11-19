//go:build unix

package lab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The slot queue tests share one host: a lock directory under the test's
// own TMPDIR with a single slot, held by the test while waiters line up.
// Locks are per open file, so a waiter in this process stands in for
// another run as well as a child process does.

func oneSlotHost(t *testing.T) string {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv(MaxLabsEnv, "1")
	dir, err := lockDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// waitForTickets returns once the slot queue holds exactly n tickets.
func waitForTickets(t *testing.T, dir string, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for {
		got := queueTickets(t, dir)
		if len(got) == n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the slot queue holds %v, want %d tickets", got, n)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func queueTickets(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "slot-queue"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if _, ok := ticketSeq(e.Name()); ok {
			names = append(names, e.Name())
		}
	}
	return names
}

func holdSlot(t *testing.T, ctx context.Context) func() {
	t.Helper()
	release, err := acquireHostSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

const slotWaiterEnv = "THINKPOL_LAB_TEST_SLOT_WAITER"

// startSlotWaiter runs TestSlotWaiterProcess in a child sharing this
// test's lock directory. The child waits for a slot, appends id to
// orderFile once it holds it, then gives it back and exits, or with hold
// set prints "holding" and keeps it until killed.
func startSlotWaiter(t *testing.T, id, orderFile string, hold bool) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSlotWaiterProcess$", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s,%s,%t", slotWaiterEnv, id, orderFile, hold))
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if hold {
		lines := bufio.NewScanner(out)
		for lines.Scan() {
			if lines.Text() == "holding" {
				return cmd
			}
		}
		t.Fatalf("the child exited without a slot: %v", lines.Err())
	}
	return cmd
}

func TestSlotWaiterProcess(t *testing.T) {
	v := os.Getenv(slotWaiterEnv)
	if v == "" {
		t.Skip("the child of the slot queue tests")
	}
	id, rest, _ := strings.Cut(v, ",")
	orderFile, hold, _ := strings.Cut(rest, ",")
	release, err := acquireHostSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hold == "true" {
		fmt.Println("holding")
		time.Sleep(time.Hour) // holds the slot until the parent kills it
	}
	appendLine(t, orderFile, id)
	release()
}

func appendLine(t *testing.T, path, line string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Error(err)
	}
}

// TestSlotsGoInArrivalOrder: waiters from other processes and from this
// one, lined up one after another behind a held slot, get it in the order
// they came, one at a time.
func TestSlotsGoInArrivalOrder(t *testing.T) {
	dir := oneSlotHost(t)
	order := filepath.Join(t.TempDir(), "order")
	release := holdSlot(t, t.Context())

	var children []*exec.Cmd
	var inProcess sync.WaitGroup
	const waiters = 8
	for i := range waiters {
		id := fmt.Sprint(i)
		if i%2 == 0 {
			children = append(children, startSlotWaiter(t, id, order, false))
		} else {
			inProcess.Go(func() {
				release, err := acquireHostSlot(t.Context())
				if err != nil {
					t.Error(err)
					return
				}
				appendLine(t, order, id)
				release()
			})
		}
		waitForTickets(t, dir, i+1)
	}
	release()
	for _, c := range children {
		if err := c.Wait(); err != nil {
			t.Errorf("a child waiter: %v", err)
		}
	}
	inProcess.Wait()

	got, err := os.ReadFile(order)
	if err != nil {
		t.Fatal(err)
	}
	if want := "0\n1\n2\n3\n4\n5\n6\n7\n"; string(got) != want {
		t.Errorf("slots went to %q, want arrival order %q", got, want)
	}
	if left := queueTickets(t, dir); len(left) != 0 {
		t.Errorf("tickets left in the queue: %v", left)
	}
}

// TestKilledWaiterLeavesNoGap: a waiter killed while queued doesn't hold
// up the one behind it, its ticket is cleared away, and a waiter killed
// while holding its slot leaks no slot.
func TestKilledWaiterLeavesNoGap(t *testing.T) {
	dir := oneSlotHost(t)
	release := holdSlot(t, t.Context())

	killed := startSlotWaiter(t, "killed", filepath.Join(t.TempDir(), "order"), false)
	waitForTickets(t, dir, 1)
	got := make(chan func(), 1)
	go func() {
		release, err := acquireHostSlot(t.Context())
		if err != nil {
			t.Error(err)
		}
		got <- release
	}()
	waitForTickets(t, dir, 2)
	if err := killed.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = killed.Wait()
	release()

	select {
	case release := <-got:
		if release == nil {
			return
		}
		release()
	case <-time.After(time.Minute):
		t.Fatal("the waiter behind a killed one never got the slot")
	}
	if left := queueTickets(t, dir); len(left) != 0 {
		t.Errorf("the killed waiter's ticket is still queued: %v", left)
	}

	if err := startSlotWaiter(t, "holder", filepath.Join(t.TempDir(), "order"), true).Process.Kill(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	holdSlot(t, ctx)()
}

// TestWaiterPastDeadlineLeavesQueue: a waiter whose wait ends leaves the
// queue, and the one behind it moves up.
func TestWaiterPastDeadlineLeavesQueue(t *testing.T) {
	dir := oneSlotHost(t)
	release := holdSlot(t, t.Context())

	first, giveUp := context.WithCancel(t.Context())
	defer giveUp()
	firstErr := make(chan error, 1)
	go func() {
		_, err := acquireHostSlot(first)
		firstErr <- err
	}()
	waitForTickets(t, dir, 1)
	got := make(chan func(), 1)
	go func() {
		release, err := acquireHostSlot(t.Context())
		if err != nil {
			t.Error(err)
		}
		got <- release
	}()
	waitForTickets(t, dir, 2)

	giveUp()
	if err := <-firstErr; err == nil || !strings.Contains(err.Error(), "lab: waiting for a free lab slot ("+MaxLabsEnv+"): context canceled") {
		t.Fatalf("a wait that ended: %v, want it to say it waited for a free lab slot", err)
	}
	waitForTickets(t, dir, 1)
	release()
	select {
	case release := <-got:
		if release != nil {
			release()
		}
	case <-time.After(time.Minute):
		t.Fatal("the waiter behind one that gave up never got the slot")
	}
}

// fakeTicket puts a ticket with sequence seq in dir's queue, locked as a
// waiter's (the lock is the returned file's), last refreshed at beat.
func fakeTicket(t *testing.T, dir string, seq uint64, beat time.Time) *os.File {
	t.Helper()
	q := filepath.Join(dir, "slot-queue")
	if err := os.MkdirAll(q, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(q, fmt.Sprintf("%020d-1-test%s", seq, slotQueueSuffix))
	f, ok, err := tryLockMode(path, true)
	if err != nil || !ok {
		t.Fatalf("locking %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := os.Chtimes(path, beat, beat); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestNewcomerWaitsBehindLiveWaiter: a free slot doesn't go to a newcomer
// while an older waiter is queued, and the newcomer's ticket is numbered
// after it.
func TestNewcomerWaitsBehindLiveWaiter(t *testing.T) {
	dir := oneSlotHost(t)
	fakeTicket(t, dir, 7, time.Now())
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	q, err := joinSlotQueue(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if q.seq != 8 {
		t.Errorf("the newcomer's ticket is number %d, want 8", q.seq)
	}
	q.leave()
	if _, err := acquireHostSlot(ctx); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a newcomer behind a live waiter: %v, want it still waiting at its deadline", err)
	}
}

// TestStuckWaiterIsSkipped: a ticket whose waiter is alive but hasn't
// refreshed it (a stopped process, a leaked lock) holds nobody up.
func TestStuckWaiterIsSkipped(t *testing.T) {
	dir := oneSlotHost(t)
	stuck := fakeTicket(t, dir, 1, time.Now().Add(-time.Hour))
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	holdSlot(t, ctx)()
	if _, err := os.Stat(stuck.Name()); err != nil {
		t.Errorf("a stuck but live waiter's ticket was removed: %v", err)
	}
}

// TestBrokenQueueDoesNotBlockSlots: whatever is in the queue's place, a
// slot that is free is taken.
func TestBrokenQueueDoesNotBlockSlots(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, q string)
	}{
		{"junk entries", func(t *testing.T, q string) {
			if err := os.MkdirAll(filepath.Join(q, "00000000000000000005-1-dir"+slotQueueSuffix), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"junk", "x-1" + slotQueueSuffix, "00000000000000000009-1-dead" + slotQueueSuffix, "99999999999999999999999-1-overflow" + slotQueueSuffix} {
				if err := os.WriteFile(filepath.Join(q, name), []byte("garbage"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"queue is a file", func(t *testing.T, q string) {
			if err := os.RemoveAll(q); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(q, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"sequence used up", func(t *testing.T, q string) {
			fakeTicket(t, filepath.Dir(q), 1<<64-1, time.Now().Add(-time.Hour))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := oneSlotHost(t)
			q := filepath.Join(dir, "slot-queue")
			if err := os.MkdirAll(q, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.spoil(t, q)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			holdSlot(t, ctx)()
		})
	}
}

// TestDeadTicketIsRemoved: a ticket nobody holds locked is a dead waiter's,
// and the next waiter that meets it clears it away.
func TestDeadTicketIsRemoved(t *testing.T) {
	dir := oneSlotHost(t)
	dead := fakeTicket(t, dir, 3, time.Now())
	_ = dead.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	holdSlot(t, ctx)()
	if left := queueTickets(t, dir); len(left) != 0 {
		t.Errorf("tickets left in the queue: %v", left)
	}
}
