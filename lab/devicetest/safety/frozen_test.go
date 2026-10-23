package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestTheSafetyCoreIsFrozen pins every file of the package and the set of
// packages its code imports (doc.go, "Frozen"): a change to the core, a
// new dependency included, is a ticket of its own, with the owner's
// approval.
func TestTheSafetyCoreIsFrozen(t *testing.T) {
	want, err := os.ReadFile("FROZEN")
	if err != nil {
		t.Fatal(err)
	}
	if got := frozenList(t); got != string(want) {
		t.Fatalf("lab/devicetest/safety differs from its pin. Changing the safety core needs a ticket of its own and "+
			"the owner's approval (doc.go, \"Frozen\"). With both, FROZEN becomes:\n%s", got)
	}
}

// frozenList is FROZEN's content for the package as it is: one
// "<sha256>  <path>" line a file, sorted, FROZEN itself left out; then
// one "import <path>" line for each package its non-test code imports.
func frozenList(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	var imports []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path == "FROZEN" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + filepath.ToSlash(path) + "\n")
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			f, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				imports = append(imports, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(imports)
	for _, p := range slices.Compact(imports) {
		b.WriteString("import " + p + "\n")
	}
	return b.String()
}
