//go:build unix

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
