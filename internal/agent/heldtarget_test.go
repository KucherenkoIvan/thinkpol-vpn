package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"math"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/reality"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

// A reality listener whose target's check keeps failing is retried by the
// server's apply retry, and its target is checked again only by the first
// retry after reality's wait ends (RR66). On a fake clock, over 25 checks,
// the gaps between checks are on no grid: for no period P from 1 s to 10 s
// (in 10 ms steps) is every gap within 50 ms of a multiple of P. A fixed
// 5 s retry puts every gap on a multiple of 5 s exactly. Each gap is at
// least the least wait reality draws after that many failures in a row
// (half of 10 s doubling, at most 2 min: reality's checkBackoff) and at
// most that wait's top plus one retry. The retry waits themselves spread
// over 3 to 7 s and average 5 s, as RetryAfter did.
//
// With random retries a gap lands within 50 ms of a multiple of P with
// odds of at most 0.1 (P = 1 s), so all 24 doing so for some P has odds
// under 900 × 1e-24.
func TestAHeldTargetIsCheckedAgainOffTheRetryGrid(t *testing.T) {
	const checksWanted = 25
	var (
		mu     sync.Mutex
		now    = time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
		checks []time.Time // when the target was dialled
		waits  []time.Duration
	)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	// The target takes each check's connection and closes it: the check
	// fails. The clock stands still meanwhile: the check waits for the
	// close, and the server's loop waits for the check.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			checks = append(checks, now)
			mu.Unlock()
			_ = c.Close()
		}
	}()

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := proto.Marshal(&transportv1.RealityListenSettings{PrivateKey: key.Bytes(), Target: target.Addr().String(), ServerNames: []string{"www.example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	tr := reality.New(reality.Options{Now: clock})
	sup := &fakeSupervisor{listen: func([]supervisor.Listener) error {
		l, err := tr.Listen(context.Background(), transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}, transport.Admission{})
		if err == nil {
			_ = l.Close()
			t.Error("the target's check passed")
		}
		return err
	}}
	// Each retry moves the clock on by its wait and fires at once, until
	// the checks wanted are seen.
	after := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		defer mu.Unlock()
		if len(checks) >= checksWanted {
			return nil
		}
		now = now.Add(d)
		waits = append(waits, d)
		c := make(chan time.Time, 1)
		c <- now
		return c
	}
	runServerSpacesIn(t, newTestSpace(t), sup, "", func(s *serverSpaces) { s.retryAfter, s.after = RetryAfter, after })
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(checks) >= checksWanted
	})

	mu.Lock()
	seen, retries := slices.Clone(checks[:checksWanted]), slices.Clone(waits)
	mu.Unlock()
	gaps := make([]time.Duration, len(seen)-1)
	for i := range gaps {
		gaps[i] = seen[i+1].Sub(seen[i])
	}
	t.Logf("%d retries; gaps between checks %v", len(retries), gaps)
	maxRetry := RetryAfter * 7 / 5
	least := 10 * time.Second
	for i, gap := range gaps {
		if gap < least/2 || gap > least+maxRetry {
			t.Errorf("gap %d after %d failed checks is %v, want %v to %v", i, i+1, gap, least/2, least+maxRetry)
		}
		least = min(2*least, 2*time.Minute)
	}
	const tolerance = 50 * time.Millisecond
	for p := time.Second; p <= 10*time.Second; p += 10 * time.Millisecond {
		onGrid := true
		for _, gap := range gaps {
			off := gap % p
			if off > tolerance && p-off > tolerance {
				onGrid = false
				break
			}
		}
		if onGrid {
			t.Fatalf("every gap is within %v of a multiple of %v: %v", tolerance, p, gaps)
		}
	}

	var sum time.Duration
	for _, w := range retries {
		if w < RetryAfter*3/5 || w > maxRetry {
			t.Fatalf("a retry after %v, want 3 to 7 s", w)
		}
		sum += w
	}
	// The mean of n waits uniform over 3 to 7 s has a standard deviation
	// of 1.15 s/√n (about 0.05 s for the ~400 retries here).
	mean := sum / time.Duration(len(retries))
	if bound := time.Duration(5 * 1.155 / math.Sqrt(float64(len(retries))) * float64(time.Second)); (mean - RetryAfter).Abs() > bound {
		t.Errorf("the %d retries average %v, want %v ± %v", len(retries), mean, RetryAfter, bound)
	}
	if lo, hi := slices.Min(retries), slices.Max(retries); lo > 3500*time.Millisecond || hi < 6500*time.Millisecond {
		t.Errorf("the retries span %v to %v, want 3 to 7 s", lo, hi)
	}
}
