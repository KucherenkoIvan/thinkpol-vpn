package lab

import (
	"fmt"
	"os"
	"testing"
)

// StreamEnv names the stream a lab test runs in, as make lab-test sets it:
// StreamDefault or StreamLong. Unset, a test runs whole, as go test run by
// hand does.
const StreamEnv = "THINKPOL_LAB_STREAM"

// The lab's two streams (lab/README.md, "Streams"): the long stream runs
// what waits minutes on real timers, beside the default stream, which
// doesn't wait for it; the default stream is everything else, under a time
// budget.
const (
	StreamDefault = "default"
	StreamLong    = "long"
)

// ResultsDirEnv names the directory a stream writes its share of a result
// assembled from both streams into (the censor matrix's RESULTS.md), for
// make lab-test to assemble once both have ended.
const ResultsDirEnv = "THINKPOL_LAB_RESULTS_DIR"

// CommitEnv names the commit a make lab-test run tests (git rev-parse HEAD,
// "-dirty" appended for uncommitted changes), as its start found it: a
// stream's share of a result carries it, and shares of different commits
// don't assemble.
const CommitEnv = "THINKPOL_LAB_COMMIT"

// Stream is the stream this process runs in: StreamDefault, StreamLong, or
// "" when StreamEnv is unset (every test runs whole). Any other value is an
// error: a misspelt stream must not run as both.
func Stream() (string, error) {
	switch s := os.Getenv(StreamEnv); s {
	case "", StreamDefault, StreamLong:
		return s, nil
	default:
		return "", fmt.Errorf("lab: %s=%q: want %q, %q or unset", StreamEnv, s, StreamDefault, StreamLong)
	}
}

// LongTest marks a test that waits minutes on real timers, the long
// stream's: in the default stream it skips. The Makefile's LAB_LONG_TESTS
// names exactly the tests that call LongTest or SplitStreams
// (TestLongTestsNamed).
func LongTest(t testing.TB) {
	t.Helper()
	s, err := Stream()
	if err != nil {
		t.Fatal(err)
	}
	if s == StreamDefault {
		t.Skip("a long test: the long stream runs it (lab/README.md, \"Streams\")")
	}
}

// SplitStreams marks a test whose long parts are the long stream's and the
// rest the default stream's, and returns the stream it runs in for it to
// pick its parts by: StreamLong, StreamDefault, or "" for all of them. Like
// LongTest's, its test is named in LAB_LONG_TESTS, so both streams run it.
func SplitStreams(t testing.TB) string {
	t.Helper()
	s, err := Stream()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
