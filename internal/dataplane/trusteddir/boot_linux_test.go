package trusteddir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheBootSessionIsTheKernelsBootID(t *testing.T) {
	s, err := BootSession()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(bootIDPath)
	if err != nil {
		t.Fatal(err)
	}
	if s+"\n" != string(want) {
		t.Fatalf("got %q, want %q", s, want)
	}
}

func TestABootIDIsOneField(t *testing.T) {
	dir := tempDir(t)
	for _, bad := range []string{"", "\n", "two fields\n"} {
		path := filepath.Join(dir, "boot_id")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if s, err := readBootID(path); err == nil {
			t.Errorf("%q read as %q", bad, s)
		}
	}
	if _, err := readBootID(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing boot id read")
	}
}
