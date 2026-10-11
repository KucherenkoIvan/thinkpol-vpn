package lab

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Capture records the IP packets a node sees on all its interfaces, with
// tcpdump, while a test runs. On the router that is everything crossing
// between the lab's networks.
type Capture struct {
	node    *Node
	proc    *Process
	mu      sync.Mutex
	packets []Packet
	changed chan struct{} // closed and replaced on every new packet
	readErr error
	read    chan struct{} // closed when the stream ends
	// truncated counts frames captured short of their length.
	truncated int

	stderr     []string      // tcpdump's last lines on stderr
	stderrDone chan struct{} // closed when tcpdump's stderr ends
}

// stderrLines bounds what is kept of tcpdump's stderr: its statistics come
// last.
const stderrLines = 20

// Capture starts capturing on the node and returns once tcpdump is
// listening. filter is a tcpdump (pcap-filter) expression, "" for all. The
// capture stops when the test ends, and the test fails if tcpdump dropped
// packets (see Dropped).
func (n *Node) Capture(t testing.TB, filter string) *Capture {
	t.Helper()
	c, err := n.startCapture(filter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Complete(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func (n *Node) startCapture(filter string) (*Capture, error) {
	stdout, stdoutW := io.Pipe()
	stderr, stderrW := io.Pipe()
	// In immediate mode libpcap's ring has one frame per snapshot length:
	// with the default 256 KiB snapshot and 2 MiB buffer, a burst of eight
	// packets overflows it. A snapshot just above the largest IP packet and
	// a 32 MiB buffer give it about 500.
	args := []string{"tcpdump", "--immediate-mode", "-U", "-n", "-i", "any", "-s", "65600", "-B", "32768", "-w", "-"}
	if filter != "" {
		args = append(args, filter)
	}
	proc, err := n.spawn(stdoutW, stderrW, args...)
	if err != nil {
		return nil, err
	}
	go func() {
		<-proc.Done()
		_ = stdoutW.Close()
		_ = stderrW.Close()
	}()
	c := &Capture{node: n, proc: proc, changed: make(chan struct{}), read: make(chan struct{}), stderrDone: make(chan struct{})}

	// tcpdump reports on stderr when it is listening, or why it isn't, and
	// what it dropped when it stops.
	listening := make(chan error, 1)
	go func() {
		defer close(c.stderrDone)
		heard := false
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			c.mu.Lock()
			c.stderr = append(c.stderr, sc.Text())
			if len(c.stderr) > stderrLines {
				c.stderr = c.stderr[1:]
			}
			c.mu.Unlock()
			if !heard && strings.HasPrefix(sc.Text(), "tcpdump: listening on") {
				heard = true
				listening <- nil
			}
		}
		_, _ = io.Copy(io.Discard, stderr)
		if !heard {
			listening <- fmt.Errorf("%s: tcpdump %q: %s", n.Name, filter, c.stderrText())
		}
	}()
	go c.readStream(stdout)

	select {
	case err := <-listening:
		if err != nil {
			_ = proc.Stop()
			return nil, err
		}
	case <-time.After(30 * time.Second):
		_ = proc.Stop()
		return nil, fmt.Errorf("%s: tcpdump did not start listening", n.Name)
	}
	return c, nil
}

func (c *Capture) readStream(r io.Reader) {
	defer close(c.read)
	defer func() { _, _ = io.Copy(io.Discard, r) }()
	pr, err := newPcapReader(r)
	if err != nil {
		c.setErr(err)
		return
	}
	defer func() {
		c.mu.Lock()
		c.truncated = pr.truncated
		c.mu.Unlock()
	}()
	for {
		pkt, err := pr.next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			c.setErr(err)
			return
		}
		pkt.Network = c.node.ifaces[pkt.Ifindex]
		c.mu.Lock()
		c.packets = append(c.packets, pkt)
		close(c.changed)
		c.changed = make(chan struct{})
		c.mu.Unlock()
	}
}

func (c *Capture) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readErr = err
}

// Packets returns the packets captured so far.
func (c *Capture) Packets() []Packet {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Packet(nil), c.packets...)
}

// Stop stops tcpdump and returns every packet it captured. Calling it again
// returns the same packets. Check Complete before trusting what is missing
// from them.
func (c *Capture) Stop() []Packet {
	_ = c.proc.Stop() // tcpdump exits non-zero on SIGTERM; the stream is complete anyway
	<-c.read
	<-c.stderrDone
	return c.Packets()
}

var droppedLine = regexp.MustCompile(`^(\d+) packets? dropped by (kernel|interface)$`)

// Dropped is how many packets tcpdump reported dropped (by the kernel's
// capture buffer or the interface) once stopped. It is an error before
// Stop, or if tcpdump reported no statistics (it was killed).
func (c *Capture) Dropped() (int, error) {
	select {
	case <-c.stderrDone:
	default:
		return 0, fmt.Errorf("%s: capture still running", c.node.Name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped, seen := 0, false
	for _, l := range c.stderr {
		if m := droppedLine.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			n, _ := strconv.Atoi(m[1])
			dropped += n
			seen = seen || m[2] == "kernel"
		}
	}
	if !seen {
		return 0, fmt.Errorf("%s: tcpdump reported no statistics: %s", c.node.Name, strings.Join(c.stderr, "; "))
	}
	return dropped, nil
}

// Complete stops the capture and reports an error unless tcpdump saw every
// packet whole and the stream decoded: a check that something is absent from a
// capture is only as good as this.
func (c *Capture) Complete() error {
	c.Stop()
	if err := c.Err(); err != nil {
		return err
	}
	n, err := c.Dropped()
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%s: tcpdump dropped %d packets: %s", c.node.Name, n, c.stderrText())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated > 0 {
		return fmt.Errorf("%s: %d packets captured short of their length", c.node.Name, c.truncated)
	}
	return nil
}

func (c *Capture) stderrText() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.TrimSpace(strings.Join(c.stderr, "\n"))
}

// Err reports a capture stream that could not be decoded.
func (c *Capture) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readErr
}

// WaitFor waits until a captured packet matches and returns the first one
// that does; it fails the test after timeout.
func (c *Capture) WaitFor(t testing.TB, timeout time.Duration, match func(Packet) bool) Packet {
	t.Helper()
	deadline := time.After(timeout)
	seen := 0
	for {
		c.mu.Lock()
		pkts, changed := c.packets[seen:], c.changed
		c.mu.Unlock()
		for _, p := range pkts {
			if match(p) {
				return p
			}
		}
		seen += len(pkts)
		select {
		case <-changed:
		case <-c.read:
			c.mu.Lock()
			more := len(c.packets) > seen
			c.mu.Unlock()
			if !more {
				t.Fatalf("%s: capture ended before a matching packet (%d seen, err %v)", c.node.Name, seen, c.Err())
			}
		case <-deadline:
			t.Fatalf("%s: no matching packet within %s (%d seen)", c.node.Name, timeout, seen)
		}
	}
}
