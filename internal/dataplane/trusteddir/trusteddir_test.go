//go:build unix

package trusteddir

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMakeMakesWhatIsMissingAndChecksIt(t *testing.T) {
	path := filepath.Join(tempDir(t), "a", "b")
	d, err := Make(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	for _, p := range []string{filepath.Dir(path), path} {
		if fi, err := os.Lstat(p); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
	if d, err = Open(path); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if _, err := Open(filepath.Join(path, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open of a missing directory: %v", err)
	}
}

func TestOthersCantChangeTheWay(t *testing.T) {
	t.Run("an ancestor others can write to", func(t *testing.T) {
		base := tempDir(t)
		if err := os.Chmod(base, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := Make(filepath.Join(base, "a")); err == nil {
			t.Fatal("accepted")
		}
		if _, err := os.Lstat(filepath.Join(base, "a")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("made under it: %v", err)
		}
	})
	t.Run("a sticky ancestor", func(t *testing.T) {
		base := tempDir(t)
		if err := os.Chmod(base, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		d, err := Make(filepath.Join(base, "a"))
		if err != nil {
			t.Fatal(err)
		}
		_ = d.Close()
		if _, err := Open(base); err == nil {
			t.Error("a sticky directory others can write to was opened as the directory itself")
		}
	})
	t.Run("a symlink on the way", func(t *testing.T) {
		base := tempDir(t)
		if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := Make(filepath.Join(base, "link", "a")); err == nil {
			t.Fatal("followed")
		}
		if _, err := os.Lstat(filepath.Join(base, "real", "a")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("made through it: %v", err)
		}
	})
}

func TestLock(t *testing.T) {
	dir := tempDir(t)
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	l, err := Lock(d, "x.lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(d, "x.lock"); !errors.Is(err, ErrLocked) {
		t.Errorf("held: %v", err)
	}
	_ = l.Close()
	if l, err = Lock(d, "x.lock"); err != nil {
		t.Fatalf("after its release: %v", err)
	}
	_ = l.Close()

	if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, "link.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(d, "link.lock"); !errors.Is(err, unix.ELOOP) {
		t.Errorf("a symlink: %v, want ELOOP", err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo.lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(d, "fifo.lock"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a FIFO: %v, want ErrNotRegular", err)
	}
}

// Files in a trusted directory are read and replaced relative to it,
// never through a symlink, and a reader never blocks on a fifo.
func TestFilesAreReadAndReplacedInTheDirectory(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if _, err := ReadFile(d, "rec"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	for _, data := range []string{"first\n", "second\n"} {
		if err := WriteFile(d, "rec", []byte(data)); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadFile(d, "rec"); err != nil || string(got) != data {
			t.Errorf("read back %q, %v; want %q", got, err, data)
		}
	}
	if fi, err := os.Lstat(filepath.Join(path, "rec")); err != nil || fi.Mode() != 0o600 {
		t.Errorf("the file: %v, %v; want a regular file, 0600", fi, err)
	}
	// The temporary file is never followed out of the directory.
	target := filepath.Join(path, "elsewhere")
	if err := os.Symlink(target, filepath.Join(path, "rec.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(d, "rec", []byte("third\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the symlink's target was written: %v", err)
	}
	if err := os.Symlink(filepath.Join(path, "rec"), filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(d, "link"); !errors.Is(err, unix.ELOOP) {
		t.Errorf("a symlink: %v, want ELOOP", err)
	}
	if err := unix.Mkfifo(filepath.Join(path, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(d, "fifo"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a fifo: %v, want ErrNotRegular", err)
	}
	for range 2 {
		if err := Remove(d, "rec"); err != nil {
			t.Errorf("Remove: %v", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(path, "rec")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("removed: %v", err)
	}
}

// A socket can't be opened at all (EOPNOTSUPP on macOS, ENXIO on Linux):
// it is no regular file. (A short test name: a socket's path is short.)
func TestASocketIsRefused(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	l, err := net.Listen("unix", filepath.Join(path, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, err := ReadFile(d, "s"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a socket: %v, want ErrNotRegular", err)
	}
}

// Names lists the directory's entries; RemoveEntry removes a file, a
// symlink (itself, never its target) or an empty directory, and leaves a
// non-empty one.
func TestEntriesAreListedAndRemovedInTheDirectory(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := WriteFile(d, "file", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(path, "target")
	if err := os.WriteFile(target, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(path, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "full", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	for range 2 { // Names reads a descriptor of its own: again, the same
		names, err := Names(d)
		slices.Sort(names)
		if want := []string{"empty", "file", "full", "link", "target"}; err != nil || !slices.Equal(names, want) {
			t.Errorf("Names %v, %v, want %v", names, err, want)
		}
	}
	for _, name := range []string{"file", "link", "empty"} {
		if err := RemoveEntry(d, name); err != nil {
			t.Errorf("RemoveEntry %s: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(path, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "kept\n" {
		t.Errorf("the symlink's target: %q, %v", got, err)
	}
	if err := RemoveEntry(d, "full"); err == nil || !strings.Contains(err.Error(), filepath.Join(path, "full")) {
		t.Errorf("a non-empty directory: %v", err)
	}
	if err := RemoveEntry(d, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing entry: %v", err)
	}
}

// Rename moves an entry within the directory, over what is there, and
// moves a symlink itself, never its target.
func TestRenameStaysInTheDirectory(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	for name, data := range map[string]string{"rec": "new\n", "aside": "old\n"} {
		if err := WriteFile(d, name, []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := Rename(d, "rec", "aside"); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFile(d, "aside"); err != nil || string(got) != "new\n" {
		t.Errorf("renamed over: %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(path, "rec")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old name: %v", err)
	}
	target := filepath.Join(path, "target")
	if err := os.WriteFile(target, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Rename(d, "link", "link.aside"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(path, "link.aside")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink moved: %v, %v", fi, err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "kept\n" {
		t.Errorf("the target: %q, %v", got, err)
	}
	if err := Rename(d, "missing", "x"); !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), filepath.Join(path, "missing")) {
		t.Errorf("a missing entry: %v", err)
	}
}

// A record carries the boot session it was written in, and reads back
// only in that one: its body for this boot, ErrOtherBoot for another,
// ErrNoBoot when no boot line comes first.
func TestRecordsAreReadOnlyInTheirBoot(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	const boot = "6F1C0D2E-0000-4000-8000-000000000001"
	body := "# a comment of the body\nline 1\n"
	if err := WriteRecord(d, "rec", "# what this is", boot, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadRecord(d, "rec", boot); err != nil || string(got) != body {
		t.Errorf("this boot: %q, %v; want %q", got, err, body)
	}
	if _, err := ReadRecord(d, "rec", "6F1C0D2E-0000-4000-8000-000000000002"); !errors.Is(err, ErrOtherBoot) {
		t.Errorf("another boot: %v, want ErrOtherBoot", err)
	}
	for name, data := range map[string]string{
		"empty":                     "",
		"comments only":             "# what this is\n\n",
		"a line before the boot":    "line 1\nboot " + boot + "\n",
		"a boot glued to its value": "boot" + boot + "\n",
		"a boot without a session":  "# what this is\nboot \nline 1\n",
		"a token before the boot":   "token 9000000000000000001 pid 4001\nboot " + boot + "\n",
	} {
		if err := os.WriteFile(filepath.Join(path, "rec"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadRecord(d, "rec", boot)
		if !errors.Is(err, ErrNoBoot) || !strings.Contains(err.Error(), filepath.Join(path, "rec")) {
			t.Errorf("%s: %v, want ErrNoBoot naming the record", name, err)
		}
		// Never the record's content: it may hold a secret, and the error
		// reaches logs and diagnostics.
		if err != nil && (strings.Contains(err.Error(), "9000000000000000001") || strings.Contains(err.Error(), "line 1\"")) {
			t.Errorf("%s: the error quotes the record: %v", name, err)
		}
	}
	if _, err := ReadRecord(d, "missing", boot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing record: %v", err)
	}
}

// WriteRecord writes only what ReadRecord reads back as written: a
// header of one comment line and a session of one field.
func TestARecordIsRefusedWhatWouldNotReadBack(t *testing.T) {
	path := tempDir(t)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	const header, boot = "# what this is", "6F1C0D2E-0000-4000-8000-000000000001"
	for name, tc := range map[string]struct{ header, boot string }{
		"a header that isn't a comment":  {"what this is", boot},
		"a header of two lines":          {header + "\n# more", boot},
		"a header ending in a newline":   {header + "\n", boot},
		"an empty header":                {"", boot},
		"an empty session":               {header, ""},
		"a session of two fields":        {header, "a b"},
		"a session with a space before":  {header, " " + boot},
		"a session with a newline after": {header, boot + "\n"},
	} {
		if err := WriteRecord(d, "rec", tc.header, tc.boot, []byte("line 1\n")); err == nil {
			t.Errorf("%s: written", name)
		}
		if _, err := os.Lstat(filepath.Join(path, "rec")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a record left: %v", name, err)
		}
	}
}
