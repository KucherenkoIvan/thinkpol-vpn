package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// CrashTraceFile, in the state directory, is where a device's service
// sends the agent's stderr (PRD S2's one exception; package service, "The
// definitions"): root's, 0600, emptied by each start once the node has
// taken what the runs before left there. A server's service names none.
const CrashTraceFile = "crash-trace"

// CrashTraceLimit bounds what a start keeps of the previous run's trace:
// its head, where a panic's message and its goroutine are (a fatal
// error's dump of every goroutine can run far longer). The file itself
// is cut to it when a start finds it longer.
const CrashTraceLimit = 64 << 10

// CrashTracePath is the crash trace file of the node's default state
// directory, the one the service's definition names.
func CrashTracePath() string { return filepath.Join(DefaultStateDir, CrashTraceFile) }

// LastRun is what the runs before under the service left on their
// stderr (TakeCrashTrace): a panic's or a fatal error's trace, or the
// error a start exited with. The zero value is none: the last run stopped
// cleanly, was killed without a word, or the agent doesn't run as a
// device's service.
type LastRun struct {
	// Trace is the head of what they wrote, up to CrashTraceLimit bytes,
	// as valid UTF-8; Truncated says there was more.
	Trace     string
	Truncated bool
	// Unreadable says why the file wasn't read ("" when it was).
	Unreadable string
}

// Crashed says the previous run left something on its stderr.
func (r LastRun) Crashed() bool { return r.Trace != "" }

// CrashTrace is what TakeCrashTrace found, and the trace file while this
// run writes to it.
type CrashTrace struct {
	// Tracing: stderr is the trace file, so the agent's log must not go
	// there too (the file would hold the whole run's log, PRD S2).
	Tracing bool
	LastRun LastRun
	// Fixed says what was wrong with the file's owner or mode and was
	// put right ("" when nothing was), for the log.
	Fixed string

	path   string
	stderr *os.File
	file   os.FileInfo
	// emptied: Release ran.
	emptied bool
}

// TakeCrashTrace reads what the runs before left in the trace file at
// path when stderr is that file: the service manager opened it for this
// run, appending (launchd's StandardErrorPath, systemd's
// StandardError=append:), so it still holds their output. It must run
// before anything of this run writes to stderr. It makes the file root's
// and 0600 whatever the manager created it with, and cuts it to its head
// (CrashTraceLimit), but empties it only once the node has the trace
// (Release): a start that fails before that adds its error after the
// trace instead of losing it. A stderr that is anything else (a terminal,
// the journal, a server's service) leaves the file alone and reports
// Tracing false.
//
// A file with more than one link isn't read or written to: it is
// emptied, removed, and stderr goes to the null device for this run
// (Detach), LastRun saying why. When the file can't be fixed or cut, stderr
// is detached the same way before the error is returned, so the error a
// failed start prints, and every restart's after it, lands nowhere
// instead of growing the file.
func TakeCrashTrace(path string, stderr *os.File) (*CrashTrace, error) {
	ct := &CrashTrace{path: path, stderr: stderr}
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
	ct.Tracing, ct.file = true, errStat
	if n := linkCount(errStat); n != 1 {
		ct.LastRun.Unreadable = fmt.Sprintf("the trace file had %d links, not read: this run's stderr goes nowhere", n)
		_ = stderr.Truncate(0)
		return ct, ct.Detach()
	}
	// Through stderr itself, so what is read, fixed and cut is the file
	// this run writes to, whatever replaced the name meanwhile. Its
	// descriptor is write-only: reading goes through a second open,
	// checked to be the same file.
	if ct.Fixed, err = fixCrashTraceFile(stderr, errStat); err != nil {
		return ct, ct.fail(err)
	}
	ct.LastRun = readCrashTrace(path, errStat)
	if errStat.Size() > CrashTraceLimit {
		if err := stderr.Truncate(CrashTraceLimit); err != nil {
			return ct, ct.fail(fmt.Errorf("cutting it to its head: %w", err))
		}
	}
	// Appending, writes go to the end; a descriptor opened without
	// O_APPEND would write at its old offset, past the end or over the
	// trace.
	if _, err := stderr.Seek(0, io.SeekEnd); err != nil && !errors.Is(err, fs.ErrInvalid) {
		return ct, ct.fail(err)
	}
	return ct, nil
}

// fail detaches stderr from the trace file, and returns err about it.
func (ct *CrashTrace) fail(err error) error {
	return errors.Join(fmt.Errorf("crash trace %s: %w", ct.path, err), ct.Detach())
}

// Release empties the trace file this run writes to, once the node has
// what the runs before left (Node.KeepLastRun). It does nothing when
// stderr isn't the file. When the file can't be emptied, stderr is
// detached (Detach).
func (ct *CrashTrace) Release() error {
	if ct == nil || !ct.Tracing || ct.emptied {
		return nil
	}
	if err := ct.stderr.Truncate(0); err != nil {
		return ct.fail(fmt.Errorf("emptying it: %w", err))
	}
	if _, err := ct.stderr.Seek(0, io.SeekStart); err != nil && !errors.Is(err, fs.ErrInvalid) {
		return ct.fail(err)
	}
	ct.emptied = true
	return nil
}

// Detach stops tracing: stderr's descriptor is pointed at the null
// device, and the trace file is removed while its name is still that
// file. A server keeps no trace (Node.KeepLastRun): its service's next
// start opens a new file, which it detaches from again until the
// service is installed anew with a server's definition.
func (ct *CrashTrace) Detach() error {
	if ct == nil || !ct.Tracing {
		return nil
	}
	ct.Tracing = false
	err := detachStderr(ct.stderr)
	if fi, lerr := os.Lstat(ct.path); lerr == nil && os.SameFile(fi, ct.file) {
		if rerr := os.Remove(ct.path); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}
	if err != nil {
		return fmt.Errorf("crash trace %s: detaching stderr: %w", ct.path, err)
	}
	return nil
}

// LogOutput is where the agent's log goes: nowhere while stderr is the
// trace file, nor while it is any other regular file under the service
// (a definition install didn't write: PRD S2's servers keep no disk
// log), else stderr.
func (ct *CrashTrace) LogOutput(stderr io.Writer, service bool) io.Writer {
	if ct.Tracing {
		return io.Discard
	}
	if f, ok := stderr.(*os.File); ok && service {
		if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
			return io.Discard
		}
	}
	return stderr
}

// CreateCrashTrace makes a new, empty trace file at path, the caller's
// (root's, as `service install` runs) and 0600, in place of whatever was
// there: the service manager then opens it as it is instead of creating
// it with its own mode, which another user could open in the moment
// before the agent fixes it.
func CreateCrashTrace(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	// The umask can only narrow 0600, but say it outright.
	return errors.Join(f.Chmod(0o600), f.Close())
}

// CleanStop is err without a clean stop's cancellation: an agent stopped
// by a signal returns nil, so its service's stderr (a device's trace)
// gets nothing.
func CleanStop(err error) error {
	if err != nil && onlyCanceled(err) {
		return nil
	}
	return err
}

func onlyCanceled(err error) bool {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			if e != nil && !onlyCanceled(e) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, context.Canceled)
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
	head := buf[:min(n, CrashTraceLimit)]
	if r.Truncated {
		head = cutAtRune(head)
	}
	// Diagnose carries it in proto3 strings, which must be UTF-8: a panic
	// may print any bytes.
	r.Trace = strings.ToValidUTF8(string(head), string(utf8.RuneError))
	return r
}

// cutAtRune drops a character the cut at the end of b split.
func cutAtRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			break
		}
	}
	return b
}
