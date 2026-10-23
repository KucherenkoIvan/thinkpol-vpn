//go:build linux || darwin

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func bootOf(s string) func() (string, error) { return func() (string, error) { return s, nil } }

func TestTheConnectRecordKeepsTheLastRequestOfItsBoot(t *testing.T) {
	dir := filepath.Join(tempDir(t), "thinkpol")
	rec := fileConnectRecord{dir: dir, boot: bootOf("boot-1")}

	// None yet, and reading makes nothing.
	if c, ok, err := rec.Load(); err != nil || ok || c {
		t.Fatalf("before any request: %v %v %v", c, ok, err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load made the directory: %v", err)
	}

	for _, want := range []bool{true, false, true} {
		if err := rec.Save(want); err != nil {
			t.Fatal(err)
		}
		if c, ok, err := rec.Load(); err != nil || !ok || c != want {
			t.Fatalf("after Save(%v): %v %v %v", want, c, ok, err)
		}
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, ConnectRecordFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the record: %v %v", fi, err)
	}

	// Another boot reads none; its first request replaces the record.
	next := fileConnectRecord{dir: dir, boot: bootOf("boot-2")}
	if c, ok, err := next.Load(); err != nil || ok || c {
		t.Fatalf("in the next boot: %v %v %v", c, ok, err)
	}
	if err := next.Save(false); err != nil {
		t.Fatal(err)
	}
	if c, ok, err := next.Load(); err != nil || !ok || c {
		t.Fatalf("the next boot's request: %v %v %v", c, ok, err)
	}
}

func TestAConnectRecordThatCantBeReadIsAnError(t *testing.T) {
	boot := bootOf("boot-1")
	for name, setup := range map[string]func(t *testing.T, dir string){
		"an unknown request": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, ConnectRecordFile), []byte(connectRecordHeader+"\nboot boot-1\nrequest maybe\n"), 0o600)
		},
		"no boot line": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, ConnectRecordFile), []byte("request connect\n"), 0o600)
		},
		"a symlink": func(t *testing.T, dir string) {
			target := filepath.Join(dir, "elsewhere")
			writeFile(t, target, []byte(connectRecordHeader+"\nboot boot-1\nrequest connect\n"), 0o600)
			if err := os.Symlink(target, filepath.Join(dir, ConnectRecordFile)); err != nil {
				t.Fatal(err)
			}
		},
		"a directory others can write to": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, ConnectRecordFile), []byte(connectRecordHeader+"\nboot boot-1\nrequest connect\n"), 0o600)
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(tempDir(t), "thinkpol")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			setup(t, dir)
			if c, ok, err := (fileConnectRecord{dir: dir, boot: boot}).Load(); err == nil || ok || c {
				t.Fatalf("got %v %v %v, want an error", c, ok, err)
			}
		})
	}
}

func TestTheHostConnectRecordIsNextToTheHostLock(t *testing.T) {
	r, ok := HostConnectRecord().(fileConnectRecord)
	if !ok || r.dir != filepath.Dir(hostLockPath) || r.boot == nil {
		t.Fatalf("got %+v", HostConnectRecord())
	}
}
