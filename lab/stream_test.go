package lab

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestLongTestsNamed: the Makefile's LAB_LONG_TESTS, which the long stream
// runs, names exactly the tests that call LongTest or SplitStreams among
// their own statements, in any test file of the module: a long test it
// misses would only skip in the default stream, and a test it names
// without either would run whole in both streams.
func TestLongTestsNamed(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^LAB_LONG_TESTS :?= (.+)$`).FindSubmatch(mk)
	if m == nil {
		t.Fatal("no LAB_LONG_TESTS in the Makefile")
	}
	named, err := regexp.Compile(strings.ReplaceAll(string(m[1]), "$$", "$"))
	if err != nil {
		t.Fatalf("LAB_LONG_TESTS: %v", err)
	}
	callers, tests := longTestCallers(t, root)
	if len(callers) == 0 {
		t.Fatal("no test calls LongTest or SplitStreams")
	}
	for _, name := range tests {
		if named.MatchString(name) != slices.Contains(callers, name) {
			t.Errorf("%s: named in LAB_LONG_TESTS (%s) %v, calls LongTest or SplitStreams %v", name, m[1], named.MatchString(name), slices.Contains(callers, name))
		}
	}
}

// longTestCallers parses every test file under root, whatever its build
// tags, and returns the top-level tests that call LongTest or SplitStreams
// and every top-level test's name.
func longTestCallers(t *testing.T, root string) (callers, tests []string) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "bin" || name == "testdata" || name == "comms") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			tests = append(tests, fn.Name.Name)
			if callsLongMarker(fn.Body) {
				callers = append(callers, fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return callers, tests
}

// callsLongMarker says whether one of a test's own statements, not one in
// a closure or a subtest, calls LongTest or SplitStreams.
func callsLongMarker(body *ast.BlockStmt) bool {
	for _, st := range body.List {
		var exprs []ast.Expr
		switch st := st.(type) {
		case *ast.ExprStmt:
			exprs = []ast.Expr{st.X}
		case *ast.AssignStmt:
			exprs = st.Rhs
		}
		for _, e := range exprs {
			call, ok := e.(*ast.CallExpr)
			if !ok {
				continue
			}
			var name string
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				if x, ok := fun.X.(*ast.Ident); ok && x.Name == "lab" {
					name = fun.Sel.Name
				}
			}
			if name == "LongTest" || name == "SplitStreams" {
				return true
			}
		}
	}
	return false
}

// TestLongTest: a long test skips in the default stream only; in the long
// stream and outside a stream it runs.
func TestLongTest(t *testing.T) {
	for _, tc := range []struct {
		stream string
		runs   bool
	}{{StreamDefault, false}, {StreamLong, true}, {"", true}} {
		t.Setenv(StreamEnv, tc.stream)
		ran := false
		t.Run("stream="+tc.stream, func(t *testing.T) {
			LongTest(t)
			ran = true
		})
		if ran != tc.runs {
			t.Errorf("%s=%q: ran %v, want %v", StreamEnv, tc.stream, ran, tc.runs)
		}
	}
}
