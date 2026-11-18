package censor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestVerdictLogWatermark: a watermark follows the entries of every packet
// it covers, one per move of the queue, none for a flush with nothing
// decided since, and close writes the last one.
func TestVerdictLogWatermark(t *testing.T) {
	var buf bytes.Buffer
	l := openVerdictLog(&buf) // flushed by the test alone
	l.write(LogEntry{Event: EventDecision, Flow: "packet 1"})
	l.handled(1)
	l.write(LogEntry{Event: EventDecision, Flow: "packet 2"})
	l.flush()
	l.flush()
	l.handled(2)
	l.handled(3)
	l.write(LogEntry{Event: EventDecision, Flow: "packet 4"})
	l.close()

	var got []string
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if e.Event == EventWatermark {
			got = append(got, fmt.Sprintf("watermark %d", e.Through))
		} else {
			got = append(got, e.Flow)
		}
	}
	want := []string{"packet 1", "packet 2", "watermark 1", "packet 4", "watermark 3"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("the log: %q, want %q", got, want)
	}
}
