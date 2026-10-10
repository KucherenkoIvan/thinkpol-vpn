package lab

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
}

// Capture starts capturing on the node and returns once tcpdump is
// listening. filter is a tcpdump (pcap-filter) expression, "" for all. The
// capture stops when the test ends.
func (n *Node) Capture(t testing.TB, filter string) *Capture {
	t.Helper()
	c, err := n.startCapture(filter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Stop() })
	return c
}

func (n *Node) startCapture(filter string) (*Capture, error) {
	stdout, stdoutW := io.Pipe()
	stderr, stderrW := io.Pipe()
	args := []string{"tcpdump", "--immediate-mode", "-U", "-n", "-i", "any", "-s", "0", "-w", "-"}
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
	c := &Capture{node: n, proc: proc, changed: make(chan struct{}), read: make(chan struct{})}

	// tcpdump reports on stderr when it is listening, or why it isn't.
	listening := make(chan error, 1)
	go func() {
		var log strings.Builder
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			log.WriteString(sc.Text() + "\n")
			if strings.HasPrefix(sc.Text(), "tcpdump: listening on") {
				listening <- nil
				_, _ = io.Copy(io.Discard, stderr)
				return
			}
		}
		listening <- fmt.Errorf("%s: tcpdump %q: %s", n.Name, filter, strings.TrimSpace(log.String()))
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
// returns the same packets.
func (c *Capture) Stop() []Packet {
	_ = c.proc.Stop() // tcpdump exits non-zero on SIGTERM; the stream is complete anyway
	<-c.read
	return c.Packets()
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
