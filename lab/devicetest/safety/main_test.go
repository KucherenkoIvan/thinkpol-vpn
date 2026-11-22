//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// The test binary is also the core's child processes: with childEnv set it
// runs the mode its first argument names, a test's own or, any other,
// through rootMain as devicetest-root does, so the tests drive real
// processes, signals and kill -9. rootMain ignores the terminal's signals
// first, so a test calls it only in a child: run in the test process, it
// would leave them ignored there and in every child started after.
const (
	childEnv   = "TPDT_TEST_CHILD"
	stateEnv   = "TPDT_TEST_STATE"   // the state directory
	surfaceEnv = "TPDT_TEST_SURFACE" // the file the test surface reads
	nonRootEnv = "TPDT_TEST_NONROOT" // allowNonRoot
)

func TestMain(m *testing.M) {
	refuseHostTools()
	if os.Getenv(childEnv) == "" {
		os.Exit(m.Run())
	}
	switch mode := os.Args[1]; mode {
	case "journal-child", "capture-child", "rootcheck":
		if err := child(mode, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "child:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(rootMain(context.Background(), os.Args[1:], childState(), os.Stdin, os.Stdout, os.Stderr))
}

// testTools are all a core test may run on a Mac: nothing that reads or
// changes the host's network. Outside the lab every other command is
// refused before it runs, in the test and in each child it starts, so no
// test, nor a mutant of one, reaches pfctl, tcpdump or the launch script's
// sudo there. pf goes through fakePf.
var testTools = []string{"/bin/cat", "/bin/sh", "/bin/sleep", "/bin/echo"}

func refuseHostTools() {
	if os.Getenv("THINKPOL_LAB") != "" {
		return
	}
	execGuard = func(path string) error {
		if slices.Contains(testTools, path) {
			return nil
		}
		return fmt.Errorf("%s: the core's tests run no host tool outside the lab", path)
	}
}

func childState() stateConfig {
	state := stateConfig{dir: os.Getenv(stateEnv), allowNonRoot: os.Getenv(nonRootEnv) != ""}
	if p := os.Getenv(surfaceEnv); p != "" {
		state.surfaces = testSurfaces(p)
	}
	return state
}

func child(mode string, args []string) error {
	switch mode {
	case "journal-child":
		return journalChild(args[0])
	case "capture-child":
		return captureChild(args[0])
	case "rootcheck":
		return rootCheck(args)
	}
	return fmt.Errorf("no mode %q", mode)
}

// testSurfaces read one file of the test's with cat: a real command over
// a real file, never the host's pf.
func testSurfaces(path string) []surface {
	return []surface{{name: "test-file", argv: []string{"/bin/cat", path}, norm: catLines, next: "put the file back"}}
}

func catLines(out output) ([]string, error) {
	if out.Code != 0 || out.Err != "" {
		return nil, fmt.Errorf("cat: exit %d %s", out.Code, out.Err)
	}
	return listingLines(out.Stdout), nil
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
	p, _ := json.Marshal(fileAction{Name: name, Content: content})
	return Spec{Kind: KindFile, Params: p}
}

func notArmed() error { return fmt.Errorf("not armed") }
func isArmed() error  { return nil }

// testHost is a host over a run directory of the test's, its surface a
// file of the test's, the baseline taken.
func testHost(t *testing.T, boot string) (*host, string) {
	t.Helper()
	dir := tempDir(t)
	surface := filepath.Join(dir, "surface.txt")
	writeFile(t, surface, "route a\nroute b\n")
	h := &host{runDir: openDir(t, filepath.Join(dir, "run")), boot: boot, surfaces: testSurfaces(surface)}
	base, err := h.snapshot(t.Context(), baselineName)
	if err != nil {
		t.Fatal(err)
	}
	h.baseline = base
	return h, surface
}

// noSurfaces is a host that compares nothing: for tests of the journal.
func noSurfaces(dir *os.File, boot string) *host {
	return &host{runDir: dir, boot: boot, surfaces: []surface{}, baseline: &snapshot{Lines: map[string][]string{}}}
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
func startSleep(t *testing.T) (*exec.Cmd, int64) {
	t.Helper()
	sleep := exec.Command("sleep", "60")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = sleep.Wait() }()
	t.Cleanup(func() { _ = sleep.Process.Kill() })
	start, err := startTime(sleep.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return sleep, start
}

func rootCheck(args []string) error {
	dir := ""
	for i, a := range args {
		if a == "-root-copy" && i+1 < len(args) {
			dir = args[i+1]
		}
	}
	if err := checkRootCopy(dir); err != nil {
		return err
	}
	fmt.Println("root copy ok")
	return removeRootCopy(dir)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
