//go:build darwin || linux

package safety

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The live reader on a capture tcpdump recorded in a lab node (a dummy
// interface on 192.0.2.1/24; the self-test's filter, so the negative
// marker, 0123456789abcdef, was filtered out by tcpdump itself).
func TestTheLiveReaderOnARecordedCapture(t *testing.T) {
	recorded, err := os.ReadFile("testdata/marker.pcap")
	if err != nil {
		t.Fatal(err)
	}
	folder := tempDir(t)
	ev, err := OpenEvidence(folder, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	main, err := ev.Create("captures/en0.pcap")
	if err != nil {
		t.Fatal(err)
	}
	// The stream arrives slowly, as from tcpdump: the copy is cut after
	// the header, while the reader waits for records.
	pr, pw := io.Pipe()
	c := &liveCapture{iface: "en0", done: make(chan struct{}), main: main, nonces: map[string]bool{}, changed: make(chan struct{})}
	go c.read(pr)
	_, _ = pw.Write(recorded[:24])
	if err := c.waitHeader(t.Context(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.cutStart(ev, "selftest/en0.pcap"); err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write(recorded[24:])
	if !c.Seen(t.Context(), "fedcba9876543210", 5*time.Second) {
		t.Fatal("the recorded marker wasn't seen")
	}
	if c.Seen(t.Context(), "0123456789abcdef", 50*time.Millisecond) {
		t.Error("a marker that isn't in the capture was seen")
	}
	if err := c.cutEnd(); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	<-c.done
	_ = main.Close()
	for _, rel := range []string{"captures/en0.pcap", "selftest/en0.pcap"} {
		got, _ := os.ReadFile(filepath.Join(folder, rel))
		if !bytes.Equal(got, recorded) {
			t.Errorf("%s: %d bytes, not the %d recorded", rel, len(got), len(recorded))
		}
	}

	// A stream that isn't a pcap fails at once, not after the run.
	bad := &liveCapture{iface: "en0", done: make(chan struct{}), nonces: map[string]bool{}, changed: make(chan struct{})}
	go bad.read(io.NopCloser(bytes.NewReader([]byte("tcpdump: en0: You don't have permission to capture on that device\n"))))
	if err := bad.waitHeader(t.Context(), 5*time.Second); err == nil {
		t.Error("a stream that isn't a pcap was taken for one")
	}
}
