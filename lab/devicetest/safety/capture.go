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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/pcap"
)

// MarkerPrefix starts the payload of a self-test marker: "tpdt-marker
// <run> <nonce>".
const MarkerPrefix = "tpdt-marker "

// Capture bounds: 128 bytes a packet (headers, the start of payloads), at
// most this many packets.
const (
	captureSnaplen = 128
	captureCount   = 200000
)

// captureAction is a tcpdump on one interface, run by the helper as root:
// the helper reads its stream, writes the pcap into the evidence itself
// and watches it for the self-test's markers. Its undo stops the process.
type captureAction struct {
	Iface  string `json:"iface"`
	Filter string `json:"filter"`
	// PID and Start name the process once it runs.
	PID   int   `json:"pid,omitempty"`
	Start int64 `json:"start,omitempty"`
}

var ifaceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

func (a *captureAction) validate() error {
	if !ifaceName.MatchString(a.Iface) {
		return fmt.Errorf("capture: bad interface %q", a.Iface)
	}
	// The filter follows `--`, and one that looks like an option is
	// refused anyway: `-w FILE` would have root's tcpdump write anywhere.
	if len(a.Filter) > 400 || strings.HasPrefix(strings.TrimSpace(a.Filter), "-") || strings.ContainsAny(a.Filter, "\n\r\x00") {
		return fmt.Errorf("capture: bad filter %q", a.Filter)
	}
	return nil
}

func (*captureAction) kind() string       { return kindCapture }
func (*captureAction) lifetime() lifetime { return volatile }
func (a *captureAction) does() string     { return fmt.Sprintf("capture on %s (%q)", a.Iface, a.Filter) }
func (a *captureAction) undoText() string { return "stop that tcpdump" }

// pre refuses a capture that names a process: only apply learns one.
func (a *captureAction) pre(_ context.Context, h *host) error {
	if a.PID != 0 || a.Start != 0 {
		return errors.New("a capture names no process before it starts")
	}
	if h.captures == nil {
		return errors.New("captures run only in the helper")
	}
	return nil
}

// apply starts tcpdump and journals its pid and start time at once, before
// waiting for it to listen: a helper killed in between leaves a process
// the undo knows.
func (a *captureAction) apply(ctx context.Context, h *host, learnt func(json.RawMessage) error) error {
	c, err := h.captures.start(a.Iface, a.Filter)
	if err != nil {
		return err
	}
	params, err := json.Marshal(captureAction{Iface: a.Iface, Filter: a.Filter, PID: c.pid, Start: c.start})
	if err == nil {
		err = learnt(params)
	}
	if err != nil {
		h.captures.stop(a.Iface)
		return err
	}
	return c.waitHeader(ctx, 5*time.Second)
}

// undo stops the capture. In the helper that started it, its table says
// what runs, whatever the journal says. In a later boot it is gone: no
// process outlives a reboot, and its pid isn't looked at (on Linux a start
// time counts from boot, so another boot's process can match it; on macOS
// it is wall-clock time and can't). Otherwise (the dead-man, a later
// restore in its boot) by the journaled pid, if that is still the process
// that started then; an intent with no pid is a tcpdump that may have
// started in the moment before its pid was journaled, which nothing can
// find now: an undo failure, until the reboot that ends it.
func (a *captureAction) undo(_ context.Context, h *host, laterBoot bool) (string, error) {
	if h.captures != nil {
		h.captures.stop(a.Iface)
		return "stopped", nil
	}
	switch {
	case laterBoot:
		return "gone with its boot: no process outlives a reboot", nil
	case a.PID != 0 && running(a.PID, a.Start):
		return "stopped by its pid", terminate(a.PID, a.Start)
	case a.PID == 0:
		return "", errors.New("its pid was never journaled: whether that tcpdump runs can't be shown; a reboot ends it")
	}
	return "gone already (it ended when its reader did)", nil
}

// terminate stops pid if it is still the process that started at start:
// TERM, then KILL after 3 s.
func terminate(pid int, start int64) error {
	if !running(pid, start) {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for range 30 {
		if !sameProcess(pid, start) || zombie(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sameProcess(pid, start) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill %d: %w", pid, err)
	}
	return nil
}

// tcpdumpArgv is the capture's command: promiscuous mode off, the filter
// after `--`. The core's tests replace it with a process that never
// listens.
var tcpdumpArgv = func(iface, filter string) []string {
	argv := []string{Tcpdump(), "-i", iface, "-n", "-p", "-U", "-s", strconv.Itoa(captureSnaplen), "-c", strconv.Itoa(captureCount), "-w", "-", "--"}
	if filter != "" {
		argv = append(argv, filter)
	}
	return argv
}

// captures are the helper's running captures, by interface.
type captures struct {
	mu   sync.Mutex
	live map[string]*liveCapture
	ev   *evidence
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
	err     error
}

func newLiveCapture(iface string, main *os.File) *liveCapture {
	return &liveCapture{iface: iface, done: make(chan struct{}), main: main, nonces: map[string]bool{}, changed: make(chan struct{})}
}

// start starts tcpdump on iface; it is in the table, and stoppable, from
// the moment it runs. A start time that can't be read fails it.
func (cs *captures) start(iface, filter string) (*liveCapture, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.live[iface] != nil {
		return nil, fmt.Errorf("a capture on %s runs already", iface)
	}
	if cs.ev == nil {
		return nil, errors.New("no evidence folder to write the capture to")
	}
	main, err := cs.ev.create("captures/" + iface + ".pcap")
	if err != nil {
		return nil, err
	}
	stderr, err := cs.ev.create("captures/" + iface + ".tcpdump.err")
	if err != nil {
		_ = main.Close()
		return nil, err
	}
	defer func() { _ = stderr.Close() }()
	c := newLiveCapture(iface, main)
	argv := tcpdumpArgv(iface, filter)
	if err := execGuard(argv[0]); err != nil {
		_ = main.Close()
		return nil, err
	}
	c.cmd = exec.Command(argv[0], argv[1:]...)
	c.cmd.Env, c.cmd.Stderr = []string{"LC_ALL=C"}, stderr
	// A group of its own: a Ctrl-C on the terminal reaches the user side,
	// whose restore ends the capture; never tcpdump first.
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := c.cmd.StdoutPipe()
	if err == nil {
		err = c.cmd.Start()
	}
	if err != nil {
		_ = main.Close()
		return nil, fmt.Errorf("tcpdump on %s: %w", iface, err)
	}
	c.pid = c.cmd.Process.Pid
	go c.read(stdout)
	if c.start, err = startTime(c.pid); err != nil {
		c.kill()
		return nil, fmt.Errorf("tcpdump on %s: its start time: %w", iface, err)
	}
	cs.live[iface] = c
	return c, nil
}

// read copies the stream into the pcap file record by record, and notes
// the markers it carries.
func (c *liveCapture) read(r io.Reader) {
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
	c.broadcastLocked()
	c.mu.Unlock()
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
		c.broadcastLocked()
	}
	return nil
}

func (c *liveCapture) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	c.broadcastLocked()
}

// broadcastLocked wakes every waiter; c.mu is held.
func (c *liveCapture) broadcastLocked() {
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

// seen waits up to timeout for a marker with nonce.
func (c *liveCapture) seen(ctx context.Context, nonce string, timeout time.Duration) bool {
	return c.waitFor(ctx, timeout, func() bool { return c.nonces[nonce] }) == nil
}

// cutStart starts a copy of the stream from here (header first) in rel.
func (c *liveCapture) cutStart(ev *evidence, rel string) error {
	f, err := ev.create(rel)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cut != nil || c.header == nil {
		_ = f.Close()
		return errors.New("a copy is being cut already, or the capture isn't listening")
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

// stop stops the helper's capture on iface, if one runs, whatever the
// journal says of it.
func (cs *captures) stop(iface string) {
	cs.mu.Lock()
	c := cs.live[iface]
	delete(cs.live, iface)
	cs.mu.Unlock()
	if c != nil {
		c.kill()
	}
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
