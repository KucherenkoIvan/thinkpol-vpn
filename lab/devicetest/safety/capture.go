//go:build darwin || linux

package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/pcap"
)

// KindCapture is CaptureAction's kind.
const KindCapture = "capture"

// MarkerPrefix starts the payload of a self-test marker: "tpdt-marker
// <run> <nonce>".
const MarkerPrefix = "tpdt-marker "

// Capture bounds: 128 bytes a packet (headers, the start of payloads), at
// most this many packets.
const (
	captureSnaplen = 128
	captureCount   = 200000
)

// CaptureAction is a tcpdump on one interface, run by the helper as root:
// the helper reads its stream, writes the pcap into the evidence itself
// and watches it for the self-test's markers. Its undo stops the process.
type CaptureAction struct {
	Iface  string `json:"iface"`
	Filter string `json:"filter"`
	// PID and Start name the process once it runs.
	PID   int   `json:"pid,omitempty"`
	Start int64 `json:"start,omitempty"`
}

var ifaceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

func (a *CaptureAction) validate() error {
	if !ifaceName.MatchString(a.Iface) {
		return fmt.Errorf("capture: bad interface %q", a.Iface)
	}
	if len(a.Filter) > 400 || bytes.ContainsAny([]byte(a.Filter), "\n\r\x00") {
		return errors.New("capture: bad filter")
	}
	return nil
}

func (*CaptureAction) Kind() string       { return KindCapture }
func (*CaptureAction) Lifetime() Lifetime { return Volatile }
func (a *CaptureAction) Does() string     { return fmt.Sprintf("capture on %s (%q)", a.Iface, a.Filter) }
func (a *CaptureAction) UndoText() string { return "stop that tcpdump" }

// Pre refuses a capture that names a process: only Apply learns one.
func (a *CaptureAction) Pre(_ context.Context, h *Host) error {
	if a.PID != 0 || a.Start != 0 {
		return errors.New("a capture names no process before it starts")
	}
	if h.captures == nil {
		return errors.New("captures run only in the helper")
	}
	return nil
}

func (a *CaptureAction) Apply(ctx context.Context, h *Host) (json.RawMessage, error) {
	c, err := h.captures.start(ctx, a.Iface, a.Filter)
	if err != nil {
		return nil, err
	}
	return json.Marshal(CaptureAction{Iface: a.Iface, Filter: a.Filter, PID: c.pid, Start: c.start})
}

// Undo stops the capture: the helper's own, or by its pid if it is still
// the process that started then (a dead-man's restore).
func (a *CaptureAction) Undo(_ context.Context, h *Host) error {
	if h.captures != nil && h.captures.stop(a.Iface, a.PID) {
		return nil
	}
	if a.PID == 0 || !sameProcess(a.PID, a.Start) {
		return nil // never started, or gone (its reader's end closed, it died of SIGPIPE)
	}
	return terminate(a.PID, a.Start)
}

// terminate stops pid: TERM, then KILL after 3 s.
func terminate(pid int, start int64) error {
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for range 30 {
		if !sameProcess(pid, start) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill %d: %w", pid, err)
	}
	return nil
}

// captures are the helper's running captures, by interface.
type captures struct {
	mu   sync.Mutex
	live map[string]*liveCapture
	ev   *Evidence
}

// liveCapture is one running tcpdump and the reader of its stream.
type liveCapture struct {
	iface string
	cmd   *exec.Cmd
	pid   int
	start int64
	done  chan struct{}

	mu      sync.Mutex
	header  []byte
	main    *os.File
	cut     *os.File
	nonces  map[string]bool
	changed chan struct{}
	records int
	err     error
}

func (cs *captures) start(ctx context.Context, iface, filter string) (*liveCapture, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.live[iface] != nil {
		return nil, fmt.Errorf("a capture on %s runs already", iface)
	}
	if cs.ev == nil {
		return nil, errors.New("no evidence folder to write the capture to")
	}
	main, err := cs.ev.Create("captures/" + iface + ".pcap")
	if err != nil {
		return nil, err
	}
	stderr, err := cs.ev.Create("captures/" + iface + ".tcpdump.err")
	if err != nil {
		_ = main.Close()
		return nil, err
	}
	c, err := startTcpdump(iface, filter, main, stderr)
	_ = stderr.Close()
	if err != nil {
		_ = main.Close()
		return nil, err
	}
	if err := c.waitHeader(ctx, 5*time.Second); err != nil {
		c.kill()
		return nil, err
	}
	cs.live[iface] = c
	return c, nil
}

func startTcpdump(iface, filter string, main, stderr *os.File) (*liveCapture, error) {
	argv := []string{tcpdump(), "-i", iface, "-n", "-U", "-s", strconv.Itoa(captureSnaplen), "-c", strconv.Itoa(captureCount), "-w", "-"}
	if filter != "" {
		argv = append(argv, filter)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tcpdump on %s: %w", iface, err)
	}
	c := &liveCapture{iface: iface, cmd: cmd, pid: cmd.Process.Pid, done: make(chan struct{}), main: main,
		nonces: map[string]bool{}, changed: make(chan struct{})}
	c.start, _ = startTime(c.pid)
	go c.read(stdout)
	return c, nil
}

// read copies the stream into the pcap file record by record, and notes
// the markers it carries.
func (c *liveCapture) read(r io.ReadCloser) {
	defer close(c.done)
	defer func() { _, _ = io.Copy(io.Discard, r) }()
	pr, err := pcap.NewReader(r)
	if err != nil {
		c.fail(fmt.Errorf("tcpdump on %s: %w", c.iface, err))
		return
	}
	c.mu.Lock()
	c.header = pr.Header()
	_, err = c.main.Write(c.header)
	c.mu.Unlock()
	c.notify()
	for err == nil {
		var rec pcap.Record
		if rec, err = pr.NextRecord(); err == nil {
			err = c.write(rec)
		}
	}
	if !errors.Is(err, io.EOF) {
		c.fail(err)
	}
}

func (c *liveCapture) write(rec pcap.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records++
	if c.cut != nil {
		if _, err := c.cut.Write(rec.Raw); err != nil {
			return err
		}
	}
	if _, err := c.main.Write(rec.Raw); err != nil {
		return err
	}
	if p := rec.Packet; rec.IsIP && p.Proto == pcap.ProtoUDP && bytes.HasPrefix(p.Payload, []byte(MarkerPrefix)) {
		f := bytes.Fields(p.Payload)
		c.nonces[string(f[len(f)-1])] = true
		close(c.changed)
		c.changed = make(chan struct{})
	}
	return nil
}

func (c *liveCapture) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *liveCapture) notify() {
	c.mu.Lock()
	defer c.mu.Unlock()
	close(c.changed)
	c.changed = make(chan struct{})
}

// waitHeader waits for the stream's header: tcpdump is listening.
func (c *liveCapture) waitHeader(ctx context.Context, timeout time.Duration) error {
	return c.waitFor(ctx, timeout, func() bool { return c.header != nil })
}

// waitFor waits until cond (read under c.mu) holds, the stream fails or
// ends, or timeout passes.
func (c *liveCapture) waitFor(ctx context.Context, timeout time.Duration, cond func() bool) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		c.mu.Lock()
		ok, err, ch := cond(), c.err, c.changed
		c.mu.Unlock()
		switch {
		case ok:
			return nil
		case err != nil:
			return err
		}
		select {
		case <-ch:
		case <-c.done:
			c.mu.Lock()
			ok = cond()
			c.mu.Unlock()
			if ok {
				return nil
			}
			return fmt.Errorf("tcpdump on %s ended", c.iface)
		case <-t.C:
			return fmt.Errorf("not within %v", timeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Seen waits up to timeout for a marker with nonce.
func (c *liveCapture) Seen(ctx context.Context, nonce string, timeout time.Duration) bool {
	return c.waitFor(ctx, timeout, func() bool { return c.nonces[nonce] }) == nil
}

// cutStart starts a copy of the stream from here (header first) in rel.
func (c *liveCapture) cutStart(ev *Evidence, rel string) error {
	f, err := ev.Create(rel)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut != nil {
		_ = f.Close()
		return errors.New("a copy is being cut already")
	}
	if _, err := f.Write(c.header); err != nil {
		_ = f.Close()
		return err
	}
	c.cut = f
	return nil
}

// cutEnd ends the copy at a record's end.
func (c *liveCapture) cutEnd() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut == nil {
		return errors.New("no copy is being cut")
	}
	err := c.cut.Close()
	c.cut = nil
	return err
}

// kill stops tcpdump and waits for the reader to finish the file.
func (c *liveCapture) kill() {
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	_ = c.cmd.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut != nil {
		_ = c.cut.Close()
		c.cut = nil
	}
	_ = c.main.Close()
}

// stop stops the capture on iface if it is the helper's and runs as pid.
func (cs *captures) stop(iface string, pid int) bool {
	cs.mu.Lock()
	c := cs.live[iface]
	if c == nil || c.pid != pid {
		cs.mu.Unlock()
		return false
	}
	delete(cs.live, iface)
	cs.mu.Unlock()
	c.kill()
	return true
}

// get is the running capture on iface.
func (cs *captures) get(iface string) (*liveCapture, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if c := cs.live[iface]; c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("no capture runs on %s", iface)
}
