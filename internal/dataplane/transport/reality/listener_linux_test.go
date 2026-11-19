//go:build linux

package reality

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// slowRootsChild names the child's part: slowRootsListen or
	// slowRootsCancel.
	slowRootsChild  = "THINKPOL_TEST_SLOW_ROOTS_CHILD"
	slowRootsListen = "listen"
	slowRootsCancel = "cancel"
	// slowRootsWait is the child's detectWait; the parent holds the child's
	// CA bundle shut for slowRootsHold, just longer.
	slowRootsWait = 2 * time.Second
	slowRootsHold = slowRootsWait + 500*time.Millisecond
	// slowRootsTimeout is the child's -test.timeout; the parent kills it a
	// little later, so the child's own timeout report comes first.
	slowRootsTimeout = 30 * time.Second
)

// REALITY's detection verifies the target against the system roots, which
// crypto/x509 reads from disk once per process, on first use: a read that
// takes longer than Listen's bounds on the target (a cold CA bundle on a
// loaded disk) doesn't fail Listen.
func TestListenDoesntChargeTheSystemRootsToTheTarget(t *testing.T) {
	if os.Getenv(slowRootsChild) == slowRootsListen {
		detectWait = slowRootsWait
		tg := newTargetAt(t, "127.0.0.1:0")
		cfg := transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, newKeys(t), tg, 0)}
		l, err := newTransport(Options{}).Listen(t.Context(), cfg, transport.Admission{Peers: transport.NewPeerTable()})
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		return
	}
	runWithSlowRoots(t, "TestListenDoesntChargeTheSystemRootsToTheTarget", slowRootsListen)
}

// A Listen whose context ends while the system roots are still being read
// returns then, not once the read ends.
func TestListenStopsWhileTheSystemRootsAreRead(t *testing.T) {
	if os.Getenv(slowRootsChild) == slowRootsCancel {
		const stop = 100 * time.Millisecond
		tg := newTargetAt(t, "127.0.0.1:0")
		cfg := transport.ListenConfig{Address: "127.0.0.1:0", Settings: listenSettingsFor(t, newKeys(t), tg, 0)}
		ctx, cancel := context.WithTimeout(t.Context(), stop)
		defer cancel()
		start := time.Now()
		l, err := newTransport(Options{}).Listen(ctx, cfg, transport.Admission{Peers: transport.NewPeerTable()})
		took := time.Since(start)
		if err == nil {
			_ = l.Close()
			t.Fatal("Listen succeeded with its context ended")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Listen: %v, want the context's end", err)
		}
		if took > slowRootsHold/2 {
			t.Fatalf("Listen returned %v after its context ended at %v: it waited for the system roots", took, stop)
		}
		return
	}
	runWithSlowRoots(t, "TestListenStopsWhileTheSystemRootsAreRead", slowRootsCancel)
}

// runWithSlowRoots runs test again in a child process, as part, with the
// child's CA bundle a FIFO held shut for slowRootsHold once the child
// opens it, and fails t unless the child passes.
func runWithSlowRoots(t *testing.T, test, part string) {
	t.Helper()
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-certificates.crt")
	if err := syscall.Mkfifo(bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	bound := slowRootsTimeout + 5*time.Second
	ctx, cancel := context.WithTimeout(t.Context(), bound)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$", "-test.timeout="+slowRootsTimeout.String())
	cmd.Env = append(envWithout(os.Environ(), slowRootsChild, "SSL_CERT_FILE", "SSL_CERT_DIR"),
		slowRootsChild+"="+part, "SSL_CERT_FILE="+bundle, "SSL_CERT_DIR="+filepath.Join(dir, "none"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var waitErr error
	exited := make(chan struct{})
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
	// Opening a FIFO to write waits for its reader: the child reading its
	// CA bundle.
	opened := make(chan *os.File, 1)
	go func() {
		f, err := os.OpenFile(bundle, os.O_WRONLY, 0)
		if err != nil {
			f = nil
		}
		opened <- f
	}()
	// freeOpener frees the opener, which waits for a reader that won't come.
	freeOpener := func() {
		if r, err := os.OpenFile(bundle, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			if f := <-opened; f != nil {
				_ = f.Close()
			}
			_ = r.Close()
		}
	}
	// killed fails t with what the child wrote, once it is dead.
	killed := func(format string, args ...any) {
		t.Helper()
		_ = cmd.Process.Kill()
		<-exited
		t.Fatalf(format+":\n%s", append(args, out.String())...)
	}
	timeout := time.NewTimer(bound)
	defer timeout.Stop()
	select {
	case f := <-opened:
		if f == nil {
			killed("opening the CA bundle to write failed")
		}
		time.Sleep(slowRootsHold)
		_ = f.Close()
	case <-exited:
		freeOpener()
		t.Fatalf("the child never read its CA bundle (exit %v):\n%s", waitErr, out.String())
	case <-timeout.C:
		freeOpener()
		killed("the child didn't read its CA bundle in %v", bound)
	}
	select {
	case <-exited:
	case <-timeout.C:
		killed("the child didn't end in %v", bound)
	}
	if waitErr != nil {
		t.Fatalf("the child, its CA bundle held shut for %v: %v\n%s", slowRootsHold, waitErr, out.String())
	}
}

// envWithout is env without the variables named.
func envWithout(env []string, names ...string) []string {
	var kept []string
	for _, kv := range env {
		if name, _, _ := strings.Cut(kv, "="); !slices.Contains(names, name) {
			kept = append(kept, kv)
		}
	}
	return kept
}
