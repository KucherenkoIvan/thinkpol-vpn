//go:build unix

package lab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGoTestLabTaggedCancelKillsTheTestBinary(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	root := writeModule(t, map[string]string{
		"hang/hang_lab_test.go": `//go:build lab

package hang

import (
	"os"
	"os/signal"
	"strconv"
	"testing"
	"time"
)

func TestHangs(t *testing.T) {
	signal.Ignore(os.Interrupt)
	f := os.Getenv("PID_FILE")
	if err := os.WriteFile(f+".tmp", []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f+".tmp", f); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Hour)
}
`,
	})
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	var out syncBuffer
	go func() {
		_, err := GoTestLabTagged(ctx, root, GoPackage{ImportPath: "example.net/tagged/hang", Dir: "hang"}, &out, []string{"PID_FILE=" + pidFile}, "-test.v")
		done <- err
	}()

	pid := waitForPID(t, pidFile, done, &out)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("GoTestLabTagged: nil after cancel, want an error\n%s", out.String())
		}
	case <-time.After(labTestWaitDelay / 2):
		t.Fatalf("GoTestLabTagged still running %v after cancel\n%s", labTestWaitDelay/2, out.String())
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("test binary %d still alive after cancel", pid)
		}
	}
}

// waitForPID waits for the test binary to write its pid to file.
func waitForPID(t *testing.T, file string, done <-chan error, out *syncBuffer) int {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case err := <-done:
			t.Fatalf("GoTestLabTagged returned before the test started: %v\n%s", err, out.String())
		default:
		}
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
			return pid
		}
	}
	t.Fatalf("the test binary never started\n%s", out.String())
	return 0
}
