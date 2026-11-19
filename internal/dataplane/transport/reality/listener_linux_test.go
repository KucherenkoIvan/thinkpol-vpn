//go:build linux

package reality

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

const (
	// slowRootsChild runs TestListenDoesntChargeTheSystemRootsToTheTarget's
	// child: one Listen, with detectWait at slowRootsWait.
	slowRootsChild = "THINKPOL_TEST_SLOW_ROOTS_CHILD"
	slowRootsWait  = 2 * time.Second
)

// REALITY's detection verifies the target against the system roots, which
// crypto/x509 reads from disk once per process, on first use: a read that
// takes longer than Listen's bounds on the target (a cold CA bundle on a
// loaded disk) doesn't fail Listen. The child process's CA bundle is a
// FIFO this test holds shut for longer than the child's bounds.
func TestListenDoesntChargeTheSystemRootsToTheTarget(t *testing.T) {
	if os.Getenv(slowRootsChild) == "1" {
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
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-certificates.crt")
	if err := syscall.Mkfifo(bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestListenDoesntChargeTheSystemRootsToTheTarget$")
	cmd.Env = append(os.Environ(), slowRootsChild+"=1", "SSL_CERT_FILE="+bundle, "SSL_CERT_DIR="+filepath.Join(dir, "none"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	// Opening a FIFO to write waits for its reader: the child reading its
	// CA bundle.
	reading := make(chan *os.File, 1)
	go func() {
		f, err := os.OpenFile(bundle, os.O_WRONLY, 0)
		if err != nil {
			close(reading)
			return
		}
		reading <- f
	}()
	select {
	case f, ok := <-reading:
		if !ok {
			t.Fatal("opening the CA bundle to write failed")
		}
		time.Sleep(slowRootsWait + time.Second)
		_ = f.Close()
		if err := <-exited; err != nil {
			t.Fatalf("Listen while the CA bundle took longer than its bounds: %v\n%s", err, out.String())
		}
	case err := <-exited:
		// Free the opener, which waits for a reader that won't come.
		if r, rerr := os.OpenFile(bundle, os.O_RDONLY|syscall.O_NONBLOCK, 0); rerr == nil {
			if f, ok := <-reading; ok {
				_ = f.Close()
			}
			_ = r.Close()
		}
		t.Fatalf("the child never read its CA bundle (exit %v):\n%s", err, out.String())
	}
}
