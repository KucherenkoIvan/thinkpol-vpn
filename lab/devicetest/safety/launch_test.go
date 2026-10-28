//go:build darwin || linux

package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// The launch script copies nothing into a temporary directory that isn't
// a sticky directory of root's, nor through a symlink to one: it refuses
// before mktemp, so this runs as the user too. The binary handed to it is
// echo: a script that wrongly went on would only print.
func TestTheLaunchScriptRefusesATemporaryDirectoryNotRootsAndSticky(t *testing.T) {
	const src = "/bin/echo"
	sum, err := fileSHA256(src)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tempDir(t), "tmp")
	if err := os.Symlink(rootCopyBase, link); err != nil {
		t.Fatal(err)
	}
	for name, base := range map[string]string{"a directory of the user's": tempDir(t), "a symlink to the real one": link} {
		before, _ := filepath.Glob(filepath.Join(base, "tpdt.*"))
		out, err := exec.Command("/bin/sh", "-c", launchScript, "devicetest-launch", src, sum, base, hasher, "rootcheck").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "not a sticky directory of root's") {
			t.Errorf("%s: %s %v", name, out, err)
		}
		after, _ := filepath.Glob(filepath.Join(base, "tpdt.*"))
		for _, d := range after {
			if !slices.Contains(before, d) {
				t.Errorf("%s: a copy was made: %s", name, d)
				_ = os.RemoveAll(d)
			}
		}
	}
}

// The launch script ignores the terminal's signals: a hangup, a Ctrl-C or
// a TERM for its process group while it copies and hashes doesn't stop
// it. The hasher here signals the whole group, then prints a wrong hash,
// so the script refuses the copy and removes it.
func TestTheLaunchScriptIgnoresTheTerminalsSignals(t *testing.T) {
	const src = "/bin/echo"
	sum, err := fileSHA256(src)
	if err != nil {
		t.Fatal(err)
	}
	hasher := filepath.Join(tempDir(t), "hasher")
	if err := os.WriteFile(hasher, []byte("#!/bin/sh\nkill -HUP 0; kill -INT 0; kill -TERM 0\necho wrong\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	before, _ := filepath.Glob(filepath.Join(rootCopyBase, "tpdt.*"))
	cmd := exec.Command("/bin/sh", "-c", launchScript, "devicetest-launch", src, sum, rootCopyBase, hasher, "rootcheck")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "hash is not the binary's: refused") {
		t.Errorf("the script didn't reach its hash check: %s %v", out, err)
	}
	after, _ := filepath.Glob(filepath.Join(rootCopyBase, "tpdt.*"))
	for _, d := range after {
		if !slices.Contains(before, d) {
			t.Errorf("a copy was left: %s", d)
			_ = os.RemoveAll(d)
		}
	}
}
