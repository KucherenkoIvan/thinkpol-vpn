package agent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// CrashTraceFile, in the state directory, is where a device's service
// sends the agent's stderr (PRD S2's one exception; package service, "The
// definitions"): root's, 0600, emptied by each start once it has read
// what the run before left there. A server's service names none.
const CrashTraceFile = "crash-trace"

// CrashTraceLimit bounds what a start keeps of the previous run's trace:
// its head, where a panic's message and its goroutine are (a fatal
// error's dump of every goroutine can run far longer).
const CrashTraceLimit = 64 << 10

// CrashTracePath is the crash trace file of the node's default state
// directory, the one the service's definition names.
func CrashTracePath() string { return filepath.Join(DefaultStateDir, CrashTraceFile) }

// LastRun is what the previous run under the service left on its stderr
// (TakeCrashTrace): a panic's or a fatal error's trace, or the error it
// exited with. The zero value is none: the last run stopped cleanly, was
// killed without a word, or the agent doesn't run as a device's service.
type LastRun struct {
	// Trace is the head of what it wrote, up to CrashTraceLimit bytes;
	// Truncated says there was more.
	Trace     string
	Truncated bool
	// Unreadable says why the file couldn't be read ("" when it was).
	Unreadable string
}

// Crashed says the previous run left something on its stderr, or its
// trace couldn't be read.
func (r LastRun) Crashed() bool { return r.Trace != "" || r.Unreadable != "" }

// CrashTrace is what TakeCrashTrace found.
type CrashTrace struct {
	// Tracing: stderr is the trace file, so the agent's log must not go
	// there too (the file would hold the whole run's log, PRD S2).
	Tracing bool
	LastRun LastRun
	// Fixed says what was wrong with the file's owner or mode and was
	// put right ("" when nothing was), for the log.
	Fixed string
}

// TakeCrashTrace reads what the previous run left in the trace file at
// path, then empties it, when stderr is that file: the service manager
// opened it for this run, appending (launchd's StandardErrorPath,
// systemd's StandardError=append:), so it still holds the previous
// run's output. It must run before anything of this run writes to
// stderr. It makes the file root's and 0600 whatever the manager created
// it with. A stderr that is anything else (a terminal, the journal, a
// server's service) leaves the file alone and reports Tracing false.
//
// A file that can't be read is still emptied, its LastRun saying why: the
// manager appends to it at every start, so one never emptied would grow
// with every crash. An error is returned only when the file can't be
// fixed or emptied; stderr is then the file all the same.
func TakeCrashTrace(path string, stderr *os.File) (CrashTrace, error) {
	var ct CrashTrace
	if stderr == nil {
		return ct, nil
	}
	errStat, err := stderr.Stat()
	if err != nil {
		return ct, nil
	}
	fileStat, err := os.Lstat(path)
	if err != nil || !fileStat.Mode().IsRegular() || !os.SameFile(errStat, fileStat) {
		return ct, nil
	}
	ct.Tracing = true
	// Through stderr itself, so what is read, fixed and emptied is the file
	// this run writes to, whatever replaced the name meanwhile. Its
	// descriptor is write-only: reading goes through a second open,
	// checked to be the same file.
	if ct.Fixed, err = fixCrashTraceFile(stderr, errStat); err != nil {
		return ct, fmt.Errorf("crash trace %s: %w", path, err)
	}
	ct.LastRun = readCrashTrace(path, errStat)
	if err := stderr.Truncate(0); err != nil {
		return ct, fmt.Errorf("crash trace %s: emptying it: %w", path, err)
	}
	// Appending, writes go to the new end; a descriptor opened without
	// O_APPEND would write at its old offset, past a hole.
	if _, err := stderr.Seek(0, io.SeekStart); err != nil && !errors.Is(err, fs.ErrInvalid) {
		return ct, fmt.Errorf("crash trace %s: %w", path, err)
	}
	return ct, nil
}

// readCrashTrace reads the head of the trace file at path, which must be
// want (stderr's file).
func readCrashTrace(path string, want os.FileInfo) LastRun {
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return LastRun{Unreadable: err.Error()}
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return LastRun{Unreadable: err.Error()}
	}
	if !os.SameFile(fi, want) {
		return LastRun{Unreadable: "the file was replaced while it was read"}
	}
	buf := make([]byte, CrashTraceLimit+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return LastRun{Unreadable: err.Error()}
	}
	r := LastRun{Truncated: n > CrashTraceLimit}
	r.Trace = string(buf[:min(n, CrashTraceLimit)])
	return r
}
