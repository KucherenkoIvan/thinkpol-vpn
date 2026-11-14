//go:build unix

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// openAsStderr opens path as a service manager opens a definition's
// stderr file for the agent: created with the manager's mode, appended to
// unless !appending.
func openAsStderr(t *testing.T, path string, appending bool) *os.File {
	t.Helper()
	flags := os.O_WRONLY | os.O_CREATE
	if appending {
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if !appending {
		if _, err := f.Seek(0, 2); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// A start reads what the previous run left, then empties the file this
// run writes to, root's (the agent's user) and 0600 whatever the manager
// made it; what this run writes then starts the file.
func TestAStartReadsThePreviousTraceThenOverwritesIt(t *testing.T) {
	for _, appending := range []bool{true, false} {
		name := "appending"
		if !appending {
			name = "at its offset"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), CrashTraceFile)
			previous := "panic: boom\n\ngoroutine 1 [running]:\nmain.main()\n"
			if err := os.WriteFile(path, []byte(previous), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			stderr := openAsStderr(t, path, appending)

			ct, err := TakeCrashTrace(path, stderr)
			if err != nil {
				t.Fatal(err)
			}
			if !ct.Tracing || ct.LastRun.Trace != previous || ct.LastRun.Truncated || ct.LastRun.Unreadable != "" || !ct.LastRun.Crashed() {
				t.Fatalf("took %+v", ct)
			}
			if !strings.Contains(ct.Fixed, "0644") {
				t.Errorf("fixed %q", ct.Fixed)
			}
			// Kept until the node has it.
			if got, _ := os.ReadFile(path); string(got) != previous {
				t.Fatalf("the file before the release holds %q", got)
			}
			if err := ct.Release(); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 || fi.Size() != 0 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
				t.Fatalf("the file after the start: %v, %d bytes, uid %d", fi.Mode(), fi.Size(), fi.Sys().(*syscall.Stat_t).Uid)
			}
			if _, err := stderr.WriteString("fatal error: this run's\n"); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(path); string(got) != "fatal error: this run's\n" {
				t.Fatalf("the file holds %q", got)
			}
			// The next start reads this run's, not the previous run's.
			ct, err = TakeCrashTrace(path, stderr)
			if err != nil || ct.LastRun.Trace != "fatal error: this run's\n" || ct.Fixed != "" {
				t.Fatalf("the next start took %+v, %v", ct, err)
			}
		})
	}
}

// A run that stopped cleanly left nothing: nothing to show.
func TestAnEmptyTraceIsNoCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), CrashTraceFile)
	ct, err := TakeCrashTrace(path, openAsStderr(t, path, true))
	if err != nil || !ct.Tracing || ct.LastRun.Crashed() || ct.LastRun != (LastRun{}) {
		t.Fatalf("took %+v, %v", ct, err)
	}
}

// What is kept is the trace's head, bounded.
func TestALongTraceKeepsItsHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), CrashTraceFile)
	long := "panic: first line\n" + strings.Repeat("goroutine\n", CrashTraceLimit/10+10)
	if err := os.WriteFile(path, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	ct, err := TakeCrashTrace(path, openAsStderr(t, path, true))
	if err != nil || !ct.LastRun.Truncated || len(ct.LastRun.Trace) != CrashTraceLimit || !strings.HasPrefix(ct.LastRun.Trace, "panic: first line\n") {
		t.Fatalf("took %d bytes, truncated %v, %v", len(ct.LastRun.Trace), ct.LastRun.Truncated, err)
	}
	// The file is cut to that head until the release.
	if fi, err := os.Stat(path); err != nil || fi.Size() != CrashTraceLimit {
		t.Fatalf("the file: %v, %v", fi.Size(), err)
	}
}

// A start that fails before the node has the trace adds its error after
// the trace instead of losing it, and the next start reads both.
func TestAFailedStartKeepsTheTrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), CrashTraceFile)
	if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, appending := range []bool{true, false} {
		stderr := openAsStderr(t, path, appending)
		if !appending {
			// At its start, as a manager may open it.
			if _, err := stderr.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := TakeCrashTrace(path, stderr); err != nil {
			t.Fatal(err)
		}
		if _, err := stderr.WriteString("thinkpol up: no map\n"); err != nil {
			t.Fatal(err)
		}
	}
	ct, err := TakeCrashTrace(path, openAsStderr(t, path, true))
	if err != nil || ct.LastRun.Trace != "panic: boom\nthinkpol up: no map\nthinkpol up: no map\n" {
		t.Fatalf("took %+v, %v", ct, err)
	}
}

// What is kept is valid UTF-8, whatever bytes the run wrote, and the cut
// at the limit doesn't split a character.
func TestTheTraceIsUTF8(t *testing.T) {
	for name, tc := range map[string]struct {
		file, want string
	}{
		"raw bytes": {"panic: \xff\n", "panic: \uFFFD\n"},
		"cut mid-character": {
			strings.Repeat("a", CrashTraceLimit-1) + "é and more",
			strings.Repeat("a", CrashTraceLimit-1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), CrashTraceFile)
			if err := os.WriteFile(path, []byte(tc.file), 0o600); err != nil {
				t.Fatal(err)
			}
			ct, err := TakeCrashTrace(path, openAsStderr(t, path, true))
			if err != nil || ct.LastRun.Trace != tc.want || !utf8.ValidString(ct.LastRun.Trace) {
				t.Fatalf("took %q, %v", ct.LastRun.Trace, err)
			}
		})
	}
}

// A trace file with another link (someone kept a name for it) isn't read
// or written to: it is emptied and removed, and stderr goes nowhere.
func TestAHardLinkedTraceIsRefused(t *testing.T) {
	dir := t.TempDir()
	path, other := filepath.Join(dir, CrashTraceFile), filepath.Join(dir, "kept")
	if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	stderr := openAsStderr(t, path, true)
	ct, err := TakeCrashTrace(path, stderr)
	if err != nil || ct.Tracing || ct.LastRun.Crashed() || !strings.Contains(ct.LastRun.Unreadable, "2 links") {
		t.Fatalf("took %+v, %v", ct, err)
	}
	if _, err := stderr.WriteString("this run's\n"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(other); err != nil || len(got) != 0 {
		t.Fatalf("the other link holds %q, %v", got, err)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("the trace file stays")
	}
	detached(t, stderr)
}

// detached checks that stderr's descriptor is the null device's.
func detached(t *testing.T, stderr *os.File) {
	t.Helper()
	fi, err := stderr.Stat()
	null, nerr := os.Stat(os.DevNull)
	if err != nil || nerr != nil || !os.SameFile(fi, null) {
		t.Fatalf("stderr is %v (%v, %v)", fi, err, nerr)
	}
}

// install's file replaces whatever was at the path, a symlink too, and
// is the caller's, 0600 and empty.
func TestCreateCrashTraceReplacesWhatWasThere(t *testing.T) {
	dir := t.TempDir()
	path, target := filepath.Join(dir, CrashTraceFile), filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("someone's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := CreateCrashTrace(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || fi.Size() != 0 || int(fi.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		t.Fatalf("the file: %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "someone's\n" {
		t.Fatalf("the symlink's target holds %q", got)
	}
}

// The log goes nowhere while stderr is the trace, or any regular file
// under the service; to stderr otherwise.
func TestTheLogStaysOffTheDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, CrashTraceFile)
	trace := openAsStderr(t, path, true)
	ct, err := TakeCrashTrace(path, trace)
	if err != nil {
		t.Fatal(err)
	}
	if ct.LogOutput(trace, false) != io.Discard {
		t.Error("the log goes to the trace")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = r.Close(), w.Close() }()
	file := openAsStderr(t, filepath.Join(dir, "elsewhere"), true)
	none := &CrashTrace{}
	for _, tc := range []struct {
		stderr  io.Writer
		service bool
		want    io.Writer
	}{{file, true, io.Discard}, {file, false, file}, {w, true, w}, {&bytes.Buffer{}, true, nil}} {
		want := tc.want
		if want == nil {
			want = tc.stderr
		}
		if got := none.LogOutput(tc.stderr, tc.service); got != want {
			t.Errorf("%T, service %v: the log goes to %T", tc.stderr, tc.service, got)
		}
	}
}

// A stop by a signal is no error, so a device's trace gets nothing.
func TestACleanStopIsNoError(t *testing.T) {
	real := errors.New("listener: address in use")
	for err, want := range map[error]bool{
		nil:              false,
		context.Canceled: false,
		errors.Join(fmt.Errorf("local API: %w", context.Canceled), nil): false,
		errors.Join(fmt.Errorf("node: %w", context.Canceled), real):     true,
		real: true,
	} {
		if got := CleanStop(err); (got != nil) != want {
			t.Errorf("CleanStop(%v) = %v", err, got)
		}
	}
}

// A server keeps no trace: under a device's definition it stops writing
// to the file at its start, removed from its space or not (its mode is
// its own, known before any map has it); a device writes on. A trace
// file a server finds otherwise is warned about.
func TestAServerKeepsNoTrace(t *testing.T) {
	s := newTestSpace(t)
	prepare := func(t *testing.T, k NodeKeys, removed bool) (*Node, *bytes.Buffer, string) {
		t.Helper()
		dir := s.stateDir(t, k, 1)
		if removed {
			writeFile(t, filepath.Join(dir, MapFileName), s.buildWithout(t, 1, k), 0o644)
		}
		var out bytes.Buffer
		logs, err := NewLogs("info", &out)
		if err != nil {
			t.Fatal(err)
		}
		cfg := testConfig(dir)
		if k == s.a {
			cfg = serverConfig(dir)
		}
		n, err := Prepare(cfg, logs, testPlatform())
		if err != nil {
			t.Fatal(err)
		}
		return n, &out, filepath.Join(dir, CrashTraceFile)
	}
	take := func(t *testing.T, path string) (*CrashTrace, *os.File) {
		t.Helper()
		if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stderr := openAsStderr(t, path, true)
		ct, err := TakeCrashTrace(path, stderr)
		if err != nil || !ct.Tracing {
			t.Fatalf("took %+v, %v", ct, err)
		}
		return ct, stderr
	}
	const reinstall = "a server under a device's service definition"

	t.Run("a server", func(t *testing.T) {
		n, out, path := prepare(t, s.a, false)
		ct, stderr := take(t, path)
		if err := n.KeepLastRun(ct); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); err == nil || ct.Tracing || !n.Status().LastRunCrashed || !strings.Contains(out.String(), reinstall) {
			t.Fatalf("tracing %v, crashed %v, log:\n%s", ct.Tracing, n.Status().LastRunCrashed, out)
		}
		detached(t, stderr)
	})
	t.Run("a device", func(t *testing.T) {
		n, out, path := prepare(t, s.b, false)
		ct, _ := take(t, path)
		if err := n.KeepLastRun(ct); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Lstat(path); err != nil || fi.Size() != 0 || !ct.Tracing || strings.Contains(out.String(), reinstall) {
			t.Fatalf("tracing %v, file %v %v, log:\n%s", ct.Tracing, fi, err, out)
		}
	})
	t.Run("a removed server", func(t *testing.T) {
		n, out, path := prepare(t, s.a, true)
		ct, stderr := take(t, path)
		if err := n.KeepLastRun(ct); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); err == nil || ct.Tracing {
			t.Fatalf("a removed server keeps tracing:\n%s", out)
		}
		detached(t, stderr)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		maps := make(chan []byte, 1)
		maps <- s.build(t, 2)
		if !n.awaitSection(ctx, maps) {
			t.Fatalf("gave up:\n%s", out)
		}
		if strings.Count(out.String(), reinstall) != 1 {
			t.Fatalf("log:\n%s", out)
		}
	})
	t.Run("a file left", func(t *testing.T) {
		n, out, path := prepare(t, s.a, false)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := n.KeepLastRun(&CrashTrace{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "holds a crash trace, which a server keeps none of") || strings.Contains(out.String(), reinstall) {
			t.Fatalf("log:\n%s", out)
		}
	})
}

// A stderr that isn't the trace file (a terminal, the journal, a server's
// service) leaves the file as it is: the agent logs to stderr as ever.
func TestAnotherStderrLeavesTheFileAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, CrashTraceFile)
	if err := os.WriteFile(path, []byte("panic: a device's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	other := openAsStderr(t, filepath.Join(dir, "elsewhere"), true)
	// A symlink to the trace isn't it either: the definition names the
	// file itself.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		stderr *os.File
	}{{path, other}, {path, nil}, {link, openAsStderr(t, path, true)}} {
		ct, err := TakeCrashTrace(tc.path, tc.stderr)
		if err != nil || ct.Tracing || ct.LastRun.Crashed() {
			t.Fatalf("%s: took %+v, %v", tc.path, ct, err)
		}
	}
	got, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	if !bytes.Equal(got, []byte("panic: a device's\n")) || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the file was changed: %q %v", got, fi.Mode())
	}
}

// A trace file someone else owns is made root's (needs root: the lab).
func TestTheTraceIsMadeRoots(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	path := filepath.Join(t.TempDir(), CrashTraceFile)
	if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	ct, err := TakeCrashTrace(path, openAsStderr(t, path, true))
	if err != nil || ct.LastRun.Trace != "panic: boom\n" || !strings.Contains(ct.Fixed, "uid 65534") {
		t.Fatalf("took %+v, %v", ct, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("uid %d gid %d mode %v", st.Uid, st.Gid, fi.Mode())
	}
}

// A start keeps tracing only on a node known to be a device: by its node
// file's mode, else, with none set, by its kind in the map; a server, a
// node the map makes a server that runs as a device by default, one the
// map doesn't hold and a state directory that can't be read stop tracing
// at once, and so does a device mode the node file doesn't give.
func TestOnlyAKnownDeviceKeepsTracing(t *testing.T) {
	s := newTestSpace(t)
	removed := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(removed, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
	withMode := func(dir string, mode Mode) string {
		writeFile(t, filepath.Join(dir, NodeFile), []byte(`{"mode": "`+string(mode)+`"}`), 0o600)
		return dir
	}
	for name, tc := range map[string]struct {
		cfg  Config
		kept bool
	}{
		"a device by its node file":          {Config{Mode: ModeDevice, StateDir: withMode(s.stateDir(t, s.a, 1), ModeDevice)}, true},
		"a server by its node file":          {Config{Mode: ModeServer, StateDir: withMode(s.stateDir(t, s.b, 1), ModeServer)}, false},
		"a server by its flag":               {Config{Mode: ModeServer, StateDir: s.stateDir(t, s.b, 1)}, false},
		"a device by its kind":               {Config{Mode: ModeDevice, StateDir: s.stateDir(t, s.b, 1)}, true},
		"a server's kind, no mode":           {Config{Mode: ModeDevice, StateDir: s.stateDir(t, s.a, 1)}, false},
		"of unknown kind":                    {Config{Mode: ModeDevice, StateDir: removed}, false},
		"a device flag over a server's file": {Config{Mode: ModeDevice, StateDir: withMode(s.stateDir(t, s.b, 1), ModeServer)}, false},
		"a config that wasn't read":          {Config{}, false},
		"a device's, unread config":          {Config{StateDir: s.stateDir(t, s.b, 1)}, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), CrashTraceFile)
			if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			stderr := openAsStderr(t, path, true)
			ct, err := TakeCrashTrace(path, stderr)
			if err != nil || !ct.Tracing {
				t.Fatalf("took %+v, %v", ct, err)
			}
			if err := ct.KeepOnlyOnADevice(tc.cfg); err != nil {
				t.Fatal(err)
			}
			_, lerr := os.Lstat(path)
			if ct.Tracing != tc.kept || (lerr == nil) != tc.kept {
				t.Fatalf("tracing %v, file %v", ct.Tracing, lerr)
			}
			if !tc.kept {
				detached(t, stderr)
			}
		})
	}
}

// A device that stops tracing makes the file anew, root's 0600 and empty,
// instead of leaving the service manager to create it with its own mode.
func TestADeviceDetachedMakesTheFileAnew(t *testing.T) {
	s := newTestSpace(t)
	path := filepath.Join(t.TempDir(), CrashTraceFile)
	if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := openAsStderr(t, path, true)
	ct, err := TakeCrashTrace(path, stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := ct.KeepOnlyOnADevice(Config{Mode: ModeDevice, StateDir: s.stateDir(t, s.b, 1)}); err != nil || !ct.Tracing {
		t.Fatalf("tracing %v, %v", ct.Tracing, err)
	}
	if err := ct.Detach(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Size() != 0 || fi.Mode().Perm() != 0o600 || ct.Tracing {
		t.Fatalf("tracing %v, file %v, %v", ct.Tracing, fi, err)
	}
	detached(t, stderr)
}

// A server's trace file that can't be removed is emptied all the same.
func TestAServersTraceIsEmptiedBeforeItIsRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes from a read-only directory")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, CrashTraceFile)
	if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := openAsStderr(t, path, true)
	ct, err := TakeCrashTrace(path, stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := ct.KeepOnlyOnADevice(Config{Mode: ModeServer}); err == nil {
		t.Fatal("removed from a read-only directory")
	}
	if got, err := os.ReadFile(path); err != nil || len(got) != 0 {
		t.Fatalf("file %q, %v", got, err)
	}
	detached(t, stderr)
}
