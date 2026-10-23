package plans

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing in this package runs unless asked: no init, no package variable
// (whose initialiser would run at start-up, as root too if root ever
// linked it).
func TestPlansRunNothingAtStartUp(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "init" && d.Recv == nil {
					t.Errorf("%s: func init", f)
				}
			case *ast.GenDecl:
				if d.Tok == token.VAR {
					t.Errorf("%s: a package variable", f)
				}
			}
		}
	}
}

func TestEveryPlanIsValid(t *testing.T) {
	for _, p := range All() {
		if err := p.Validate(); err != nil {
			t.Error(err)
		}
	}
}
