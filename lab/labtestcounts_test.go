package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMakefileCountsCells: make lab-test's last line counts the cells the
// streams listed beside their shares (known flakes, cells not judged) as
// the matrix counts them in RESULTS.md: each cell once, however many
// streams listed it, sorted, "<label>: <n> (<cells>)", and nothing when no
// stream listed one or none wrote its list. The recipe counts both lists
// with it, joins both into one tail (each part only when not empty) and
// ends every last line (failed, over budget, passed) with that tail.
func TestMakefileCountsCells(t *testing.T) {
	if testing.Short() {
		t.Skip("runs make")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make here")
	}
	show := filepath.Join(t.TempDir(), "show.mk")
	if err := os.WriteFile(show, []byte("show-counts:\n\t@$(call LAB_COUNT_CELLS,NOT JUDGED,\"$(DIR)\"/not-judged-*.txt)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	count := func(files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command("make", "--no-print-directory", "-s", "-C", "..", "-f", "Makefile", "-f", show, "show-counts", "DIR="+dir).Output()
		if err != nil {
			t.Fatalf("make: %v", err)
		}
		return string(out)
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"both streams, one cell in both", map[string]string{
			"not-judged-default.txt": "reality / active prober\nhttps / active prober\n",
			"not-judged-long.txt":    "reality / active prober\n",
			"known-flakes-long.txt":  "udp / fully-encrypted\n",
		}, "NOT JUDGED: 2 (https / active prober, reality / active prober)"},
		{"empty lists", map[string]string{"not-judged-default.txt": "", "not-judged-long.txt": ""}, ""},
		{"no list", nil, ""},
	} {
		if got := count(c.files); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	mk, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`flakes=$$($(call LAB_COUNT_CELLS,KNOWN FLAKES,"$$tmp"/known-flakes-*.txt))`,
		`unjudged=$$($(call LAB_COUNT_CELLS,NOT JUDGED,"$$tmp"/not-judged-*.txt))`,
		`counts="$${flakes:+; $$flakes}$${unjudged:+; $$unjudged}"`,
		`echo "lab-test: FAILED:$$failed$${over:+; also OVER BUDGET ($$over)}$$counts"; exit 1;`,
		`echo "lab-test: tests passed, OVER BUDGET ($$over)$$counts"; exit 3;`,
		`echo "lab-test: passed$$counts"`,
	} {
		if !strings.Contains(string(mk), want) {
			t.Errorf("make lab-test's recipe lacks %s", want)
		}
	}
}
