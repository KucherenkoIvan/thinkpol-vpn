//go:build darwin || linux

package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// The live reader on a capture tcpdump recorded in a lab node (a dummy
// interface on 192.0.2.1/24; the self-test's filter, so the negative
// marker, 0123456789abcdef, was filtered out by tcpdump itself).
func TestTheLiveReaderCopiesTheStreamAndSeesOnlyItsMarkers(t *testing.T) {
	recorded, err := os.ReadFile("testdata/marker.pcap")
	if err != nil {
		t.Fatal(err)
	}
	folder := tempDir(t)
	ev, err := openEvidence(folder, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	main, err := ev.create("captures/en0.pcap")
	if err != nil {
		t.Fatal(err)
	}
	// The stream arrives slowly, as from tcpdump: the copy is cut after
	// the header, while the reader waits for records.
	pr, pw := io.Pipe()
	c := newLiveCapture("en0", main)
	go c.read(pr)
	_, _ = pw.Write(recorded[:24])
	if err := c.waitHeader(t.Context(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.cutStart(ev, "selftest/en0.pcap"); err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write(recorded[24:])
	if !c.seen(t.Context(), "fedcba9876543210", 5*time.Second) {
		t.Fatal("the recorded marker wasn't seen")
	}
	if c.seen(t.Context(), "0123456789abcdef", 50*time.Millisecond) {
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
	bad := newLiveCapture("en0", nil)
	go bad.read(bytes.NewReader([]byte("tcpdump: en0: You don't have permission to capture on that device\n")))
	if err := bad.waitHeader(t.Context(), 5*time.Second); err == nil {
		t.Error("a stream that isn't a pcap was taken for one")
	}
}

func TestParametersRootWouldMisreadAreRefused(t *testing.T) {
	for _, s := range []Spec{
		{Kind: "shell", Params: []byte(`{"cmd":"true"}`)},
		{Kind: KindFile, Params: []byte(`{"name":"../x","content":""}`)},
		{Kind: KindFile, Params: []byte(`{"name":"x","content":"","extra":1}`)},
		{Kind: KindFile, Params: []byte(`null`)},
		{Kind: kindCapture, Params: []byte(`null`)},
		{Kind: kindPfSkip, Params: []byte(`null`)},
		{Kind: kindCapture, Params: []byte(`{"iface":"en0; true","filter":""}`)},
		// After `--` or not, a filter that looks like an option is
		// refused: -w would have root's tcpdump write any file.
		{Kind: kindCapture, Params: []byte(`{"iface":"en0","filter":"-w/etc/pf.conf"}`)},
		{Kind: kindCapture, Params: []byte(`{"iface":"en0","filter":" -wfile"}`)},
		{Kind: kindPfSkip, Params: []byte(`{"iface":"lo\nanchor \"x\""}`)},
		{Kind: kindPfSkip, Params: []byte(`{"prepend":"pass quick all"}`)},
	} {
		if _, _, err := Describe(s); err == nil {
			t.Errorf("%s %s accepted", s.Kind, s.Params)
		}
	}
	if args := tcpdumpArgv("en0", "ip6"); args[len(args)-2] != "--" || !strings.Contains(strings.Join(args, " "), " -p ") {
		t.Errorf("tcpdump's arguments: %q", args)
	}
}

// captureChild starts a capture whose process never listens and blocks
// in the wait for its header, as a helper killed in that window would.
func captureChild(path string) error {
	tcpdumpArgv = func(string, string) []string { return []string{"/bin/sleep", "60"} }
	dir, err := trusteddir.Make(filepath.Join(path, "run"))
	if err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(path, "evidence"), 0o700); err != nil {
		return err
	}
	ev, err := openEvidence(filepath.Join(path, "evidence"), os.Getuid(), os.Getgid())
	if err != nil {
		return err
	}
	j, err := createJournal(dir, "child", "boot-a")
	if err != nil {
		return err
	}
	h := &host{runDir: dir, boot: "boot-a", baseline: &snapshot{}, evidence: ev, captures: &captures{live: map[string]*liveCapture{}, ev: ev}}
	params, _ := json.Marshal(captureAction{Iface: "en0"})
	_, err = (&engine{h: h, j: j, armed: isArmed}).do(context.Background(), Spec{Kind: kindCapture, Params: params})
	return err
}

func TestAHelperKilledBeforeItsCaptureListensLeavesNoProcess(t *testing.T) {
	base := tempDir(t)
	cmd := childCommand(t, nil, "capture-child", base)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	journalPath := filepath.Join(base, "run", journalName)
	eventually(t, 10*time.Second, "the capture's pid journaled", func() bool {
		b, _ := os.ReadFile(journalPath)
		return bytes.Contains(b, []byte(`"pid":`))
	})
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()

	dir := openDir(t, filepath.Join(base, "run"))
	j, err := openJournal(dir, "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	var a captureAction
	if p := j.pending(); len(p) != 1 || json.Unmarshal(p[0].Params, &a) != nil || a.PID == 0 {
		t.Fatalf("pending: %+v", p)
	}
	if !running(a.PID, a.Start) {
		t.Fatal("the capture's process didn't outlive its helper: nothing to test")
	}
	res := (&engine{h: noSurfaces(dir, "boot-a"), j: j, armed: refuseChanges}).restore(t.Context(), "test")
	if res.Verdict != Clean {
		t.Errorf("restore: %+v", res)
	}
	eventually(t, 5*time.Second, "the orphaned capture stopped", func() bool { return !running(a.PID, a.Start) })
}
