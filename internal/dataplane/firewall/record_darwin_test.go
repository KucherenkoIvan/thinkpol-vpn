package firewall

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

func TestAGuardReferenceIsHeldOnlyByThisBootsRecord(t *testing.T) {
	boot, err := trusteddir.BootSession()
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "missing")
	if held, err := GuardReferenceHeld(missing); err != nil || held {
		t.Errorf("a missing directory: %v %v", held, err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Error("the reader made the directory")
	}
	for _, tc := range []struct {
		name, boot string
		held       bool
	}{{"this boot", boot, true}, {"another boot", "another-boot", false}} {
		dir := filepath.Join(base, tc.name)
		d, err := trusteddir.Make(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := trusteddir.WriteRecord(d, tokenRecord, tokenHeader, tc.boot, []byte("token 42 pid 7\n")); err != nil {
			t.Fatal(err)
		}
		_ = d.Close()
		if held, err := GuardReferenceHeld(dir); err != nil || held != tc.held {
			t.Errorf("%s: held %v %v", tc.name, held, err)
		}
	}
	odd := filepath.Join(base, "odd")
	if err := os.MkdirAll(filepath.Join(odd, tokenRecord), 0o700); err != nil {
		t.Fatal(err)
	}
	if held, err := GuardReferenceHeld(odd); err != nil || held {
		t.Errorf("a record that is a directory: %v %v", held, err)
	}
	link := filepath.Join(base, "link")
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "this boot", tokenRecord), filepath.Join(link, tokenRecord)); err != nil {
		t.Fatal(err)
	}
	if held, err := GuardReferenceHeld(link); err != nil || held {
		t.Errorf("a symlinked record: %v %v", held, err)
	}
}
