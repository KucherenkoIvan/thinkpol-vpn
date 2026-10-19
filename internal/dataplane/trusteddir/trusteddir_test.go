//go:build unix

package trusteddir

import (
	"errors"
	"os"
	"path/filepath"
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
	if _, err := Lock(d, "link.lock"); err == nil {
		t.Error("a symlink was followed")
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo.lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(d, "fifo.lock"); err == nil {
		t.Error("a FIFO was taken")
	}
}

// Files in a trusted directory are read and replaced relative to it,
// never through a symlink, and a reader never blocks on a fifo.
func TestFilesAreReadAndReplacedInPlace(t *testing.T) {
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
