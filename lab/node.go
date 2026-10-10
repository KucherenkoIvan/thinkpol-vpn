package lab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Node is a running node of a lab.
type Node struct {
	Name      string
	Container string // the Docker container ID
	lab       *Lab
	addrs     map[string]NodeAddr // by network
	ifaces    map[int]string      // interface index → network
	ifnames   map[string]string   // network → interface name
}

// Interface is the name of the node's interface on a network (eth0, …).
func (n *Node) Interface(network string) string { return n.ifnames[network] }

// NodeAddr is a node's addresses on one network. IPv6 is invalid on an
// IPv4Only network.
type NodeAddr struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
	mac  string
}

// Addr returns the node's addresses on a network; a network the node isn't
// on is a bug in the test and panics.
func (n *Node) Addr(network string) NodeAddr {
	a, ok := n.addrs[network]
	if !ok {
		panic(fmt.Sprintf("lab: node %s is not on network %q", n.Name, network))
	}
	return a
}

// IPv4 is the node's IPv4 address on a network.
func (n *Node) IPv4(network string) netip.Addr { return n.Addr(network).IPv4 }

// IPv6 is the node's IPv6 address on a network.
func (n *Node) IPv6(network string) netip.Addr { return n.Addr(network).IPv6 }

// execTimeout bounds MustExec and WriteFile; use Exec with a context for
// longer commands.
const execTimeout = 2 * time.Minute

// Exec runs a command in the node and waits for it. A non-zero exit is an
// error; the Result is filled in either way.
func (n *Node) Exec(ctx context.Context, args ...string) (Result, error) {
	return n.exec(ctx, nil, args...)
}

func (n *Node) exec(ctx context.Context, stdin io.Reader, args ...string) (Result, error) {
	flags := []string{"exec"}
	if stdin != nil {
		flags = append(flags, "-i")
	}
	res, err := run(ctx, stdin, nil, "docker", append(append(flags, n.Container), args...)...)
	switch {
	case err != nil && res.ExitCode != 0:
		return res, fmt.Errorf("%s: %s: exit %d: %s", n.Name, describe(args[0], args[1:]), res.ExitCode, strings.TrimSpace(res.Stderr))
	case err != nil:
		return res, fmt.Errorf("%s: %w", n.Name, err)
	}
	return res, nil
}

// MustExec runs a command in the node, fails the test unless it exits 0,
// and returns its stdout.
func (n *Node) MustExec(t testing.TB, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	res, err := n.Exec(ctx, args...)
	if err != nil {
		t.Fatalf("%v\nstdout:\n%s", err, res.Stdout)
	}
	return res.Stdout
}

// WriteFile writes a file in the node, creating its directory.
func (n *Node) WriteFile(t testing.TB, path string, data []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	script := `mkdir -p "$(dirname "$1")" && cat > "$1"`
	if _, err := n.exec(ctx, bytes.NewReader(data), "sh", "-ec", script, "sh", path); err != nil {
		t.Fatal(err)
	}
}

// ExportFS writes the node's whole filesystem to w as a tar stream (docker
// export), for checks on what a node leaves on disk. Mounted volumes such as
// BinDir and SrcDir are not included. Tests read nodes' files this way or
// through Exec, never through block devices.
func (n *Node) ExportFS(ctx context.Context, w io.Writer) error {
	cmd := exec.CommandContext(ctx, "docker", "export", n.Container)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = w, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: docker export: %w: %s", n.Name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

var processSeq atomic.Uint64

// Process is a command running in a node in the background.
type Process struct {
	node    *Node
	pidFile string
	cmd     *exec.Cmd
	out     *syncBuffer
	done    chan struct{}
	err     error
	stop    sync.Once
}

// Start runs a command in the node in the background. It is stopped when the
// test ends, and its output goes to the test log if the test failed.
func (n *Node) Start(t testing.TB, args ...string) *Process {
	t.Helper()
	out := &syncBuffer{}
	p, err := n.spawn(out, out, args...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Stop()
		if t.Failed() {
			t.Logf("%s: %s:\n%s", n.Name, strings.Join(args, " "), p.Output())
		}
	})
	return p
}

// spawn starts a command through docker exec. The command records its pid
// so Stop can signal it: killing the docker client would leave it running.
func (n *Node) spawn(stdout, stderr io.Writer, args ...string) (*Process, error) {
	pidFile := fmt.Sprintf("/run/lab/proc-%d.pid", processSeq.Add(1))
	script := `mkdir -p /run/lab && echo $$ > "$0" && exec "$@"`
	cmd := exec.Command("docker", append([]string{"exec", n.Container, "sh", "-c", script, pidFile}, args...)...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	p := &Process{node: n, pidFile: pidFile, cmd: cmd, done: make(chan struct{})}
	if b, ok := stdout.(*syncBuffer); ok {
		p.out = b
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: start %s: %w", n.Name, strings.Join(args, " "), err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// Done is closed when the process has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err is the process's exit error, once Done is closed.
func (p *Process) Err() error {
	<-p.done
	return p.err
}

// Output is what the process wrote to stdout and stderr so far.
func (p *Process) Output() string {
	if p.out == nil {
		return ""
	}
	return p.out.String()
}

// Stop sends SIGTERM, then SIGKILL after five seconds, and waits for the
// process to exit. It returns the exit error, which after a signal is
// usually non-nil.
func (p *Process) Stop() error {
	p.stop.Do(func() {
		select {
		case <-p.done:
			return
		default:
		}
		p.signal("TERM")
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			p.signal("KILL")
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				_ = p.cmd.Process.Kill()
				<-p.done
			}
		}
	})
	<-p.done
	return p.err
}

// signal waits briefly for the pid file: a process stopped right after
// Start may not have written it yet.
func (p *Process) signal(sig string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	script := `for i in $(seq 50); do [ -s "$0" ] && exec kill -` + sig + ` "$(cat "$0")"; sleep 0.1; done`
	_, _ = p.node.Exec(ctx, "sh", "-c", script, p.pidFile)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
