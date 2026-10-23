//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// The test binary is also the core's child processes: with childEnv set it
// runs the mode its first argument names (as devicetest's main does), so
// the tests drive real processes, signals and kill -9.
const (
	childEnv   = "TPDT_TEST_CHILD"
	stateEnv   = "TPDT_TEST_STATE"   // the state directory
	surfaceEnv = "TPDT_TEST_SURFACE" // the file the test surface reads
	nonRootEnv = "TPDT_TEST_NONROOT" // AllowNonRoot
)

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "" {
		os.Exit(m.Run())
	}
	if err := child(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func child(mode string, args []string) error {
	ctx := context.Background()
	state := StateConfig{Dir: os.Getenv(stateEnv), AllowNonRoot: os.Getenv(nonRootEnv) != ""}
	if p := os.Getenv(surfaceEnv); p != "" {
		state.Surfaces = testSurfaces(p)
	}
	switch mode {
	case "helper":
		return HelperMain(ctx, args, state, os.Stdin, os.Stdout, os.Stderr)
	case "deadman":
		return DeadmanMain(ctx, args, state)
	case "restore":
		return RestoreMain(ctx, args, state, os.Stdout)
	case "journal-child":
		return journalChild(args[0])
	case "rootcheck":
		return rootCheck(args)
	}
	return fmt.Errorf("no mode %q", mode)
}

// testSurfaces read one file of the test's with cat: a real command over
// a real file, never the host's pf.
func testSurfaces(path string) []Surface {
	return []Surface{{Name: "test-file", Argv: []string{"/bin/cat", path}, Norm: catLines, Next: "put the file back"}}
}

func catLines(out output) ([]string, error) {
	if out.Code != 0 || out.Err != "" {
		return nil, fmt.Errorf("cat: exit %d %s", out.Code, out.Err)
	}
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out.Stdout)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// tempDir is a directory trusteddir accepts (macOS's temp dir is reached
// through the /var symlink).
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func openDir(t *testing.T, path string) *os.File {
	t.Helper()
	d, err := trusteddir.Make(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func fileSpec(name, content string) Spec {
	p, _ := json.Marshal(FileAction{Name: name, Content: content})
	return Spec{Kind: KindFile, Params: p}
}

func notArmed() error { return fmt.Errorf("not armed") }
func isArmed() error  { return nil }

// testHost is a Host over a run directory of the test's, its surface a
// file of the test's, the baseline taken.
func testHost(t *testing.T, boot string) (*Host, string) {
	t.Helper()
	dir := tempDir(t)
	surface := filepath.Join(dir, "surface.txt")
	writeFile(t, surface, "route a\nroute b\n")
	h := &Host{RunDir: openDir(t, filepath.Join(dir, "run")), Boot: boot, Surfaces: testSurfaces(surface)}
	base, err := h.Snapshot(t.Context(), "00-baseline")
	if err != nil {
		t.Fatal(err)
	}
	h.Baseline = base
	return h, surface
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func present(dir *os.File, name string) bool {
	var st unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}

// childCommand runs the test binary as a child in mode.
func childCommand(t *testing.T, env []string, mode string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{mode}, args...)...)
	cmd.Env = append(append(os.Environ(), childEnv+"=1"), env...)
	return cmd
}

// eventually polls cond until it holds or timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startSleep starts a harmless process of the test's, reaped as soon as it
// ends (a zombie still has its pid).
func startSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	sleep := exec.Command("sleep", "60")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = sleep.Wait() }()
	t.Cleanup(func() { _ = sleep.Process.Kill() })
	return sleep
}

func rootCheck(args []string) error {
	dir := ""
	for i, a := range args {
		if a == "-root-copy" && i+1 < len(args) {
			dir = args[i+1]
		}
	}
	if err := CheckRootCopy(dir); err != nil {
		return err
	}
	fmt.Println("root copy ok")
	return removeRootCopy(dir)
}
