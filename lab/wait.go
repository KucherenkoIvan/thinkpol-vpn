package lab

import (
	"testing"
	"time"
)

// Eventually polls cond until it returns nil, and fails the test with the
// last error once timeout has passed.
func Eventually(t testing.TB, timeout time.Duration, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := cond()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %v", timeout, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
