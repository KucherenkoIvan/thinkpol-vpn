//go:build darwin || linux

package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
