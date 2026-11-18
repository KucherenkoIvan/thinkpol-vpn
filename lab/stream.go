package lab

import (
	"fmt"
	"os"
)

// StreamEnv names the stream a lab test runs in, as make lab-test sets it:
// StreamDefault or StreamLong. Unset, a test runs whole, as go test run by
// hand does.
const StreamEnv = "THINKPOL_LAB_STREAM"

// The lab's two streams (lab/README.md, "Streams"): the long stream runs
// what waits minutes on real timers, beside the default stream and never in
// its way; the default stream is everything else, under a time budget.
const (
	StreamDefault = "default"
	StreamLong    = "long"
)

// ResultsDirEnv names the directory a stream writes its share of a result
// assembled from both streams into (the censor matrix's RESULTS.md), for
// make lab-test to assemble once both have ended.
const ResultsDirEnv = "THINKPOL_LAB_RESULTS_DIR"

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
