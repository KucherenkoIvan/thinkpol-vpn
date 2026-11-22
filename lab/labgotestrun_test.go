package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMakefileLabGotestPassesRunVerbatim: make lab-gotest hands RUN and SKIP
// to labctl byte for byte, from the command line or the environment, so a
// regexp's $ anchors and $/ subtest separators aren't read as make
// variables. A prerequisite added to lab-gotest inherits its exports and
// prints them, then fails, before labctl is built.
func TestMakefileLabGotestPassesRunVerbatim(t *testing.T) {
	if testing.Short() {
		t.Skip("runs make")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make here")
	}
	show := filepath.Join(t.TempDir(), "show.mk")
	rule := "lab-gotest: show-lab-gotest-env\nshow-lab-gotest-env:\n\t@printf '%s\\n%s\\n' \"$$LAB_RUN\" \"$$LAB_SKIP\"; exit 1\n"
	if err := os.WriteFile(show, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	run, skip := `^TestCensorMatrix$/^(udp|reality)$/^off$`, `^TestSlow$|x$y`
	for _, fromEnv := range []bool{false, true} {
		args := []string{"--no-print-directory", "-s", "-C", "..", "-f", "Makefile", "-f", show, "lab-gotest", "PKG=./lab"}
		env := os.Environ()
		if fromEnv {
			env = append(env, "RUN="+run, "SKIP="+skip)
		} else {
			args = append(args, "RUN="+run, "SKIP="+skip)
		}
		cmd := exec.Command("make", args...)
		cmd.Env = env
		out, _ := cmd.Output() // the shown prerequisite fails on purpose
		if got, want := string(out), run+"\n"+skip+"\n"; got != want {
			t.Errorf("from the environment %v: labctl gets -run and -skip\n%q, want\n%q", fromEnv, strings.TrimSpace(got), strings.TrimSpace(want))
		}
	}
}
