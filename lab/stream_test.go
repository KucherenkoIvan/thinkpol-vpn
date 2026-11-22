package lab

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestLongTestsNamed: the Makefile's LAB_LONG_TESTS, which the long stream
// runs, names exactly the tests that call LongTest or SplitStreams, in any
// file of the module: a long test it misses would only skip in the
// default stream, and a test it names without either would run whole in
// both streams. A call may only be one of a top-level test's own
// statements in a package under lab/ (checkLongMarkers): one in a subtest
// or a helper hides its test from the check, and a test outside lab/ runs
// in the node phase, which no stream reaches.
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
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "bin" || name == "testdata" || name == "comms") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	module := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindSubmatch(gomod)
	if module == nil {
		t.Fatal("no module line in go.mod")
	}
	c := checkLongMarkers(fset, string(module[1]), files)
	for _, bad := range c.misplaced {
		t.Error(bad)
	}
	if len(c.callers) == 0 {
		t.Fatal("no test calls LongTest or SplitStreams")
	}
	for _, name := range c.tests {
		if named.MatchString(name) != slices.Contains(c.callers, name) {
			t.Errorf("%s: named in LAB_LONG_TESTS (%s) %v, calls LongTest or SplitStreams %v", name, m[1], named.MatchString(name), slices.Contains(c.callers, name))
		}
	}
}

// longMarkers are lab's functions that mark a long stream test.
var longMarkers = map[string]bool{"LongTest": true, "SplitStreams": true}

// longMarkerUnitTests are lab's own tests of the markers, which call them
// in subtests on purpose.
var longMarkerUnitTests = map[string]bool{"TestLongTest": true}

// longMarkerCheck is what checkLongMarkers found.
type longMarkerCheck struct {
	callers   []string // top-level tests that call a marker as one of their own statements
	tests     []string // every top-level test of a _test.go file
	misplaced []string // every other use of a marker, "file:line: why"
}

// checkLongMarkers finds every use of LongTest and SplitStreams in files
// (by slash path from the module's root; module is its path), by name in
// package lab and under whatever name a file imports lab as. The only
// allowed use is a call that is a top-level statement (or the right side
// of one) of a top-level test in a _test.go file of a package under lab/.
func checkLongMarkers(fset *token.FileSet, module string, files map[string]*ast.File) longMarkerCheck {
	var c longMarkerCheck
	labPath := module + "/lab"
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		f := files[rel]
		dir := path.Dir(rel)
		underLab := dir == "lab" || strings.HasPrefix(dir, "lab/")
		isTest := strings.HasSuffix(rel, "_test.go")
		bare := dir == "lab" && f.Name.Name == "lab"
		names := map[string]bool{}
		for _, imp := range f.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != labPath {
				continue
			}
			switch {
			case imp.Name == nil:
				names["lab"] = true
			case imp.Name.Name == ".":
				bare = true
			default:
				names[imp.Name.Name] = true
			}
		}
		isMarker := func(e ast.Expr) bool {
			switch e := e.(type) {
			case *ast.Ident:
				return bare && longMarkers[e.Name]
			case *ast.SelectorExpr:
				x, ok := e.X.(*ast.Ident)
				return ok && names[x.Name] && longMarkers[e.Sel.Name]
			}
			return false
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			isTestFn := isTest && fn != nil && fn.Recv == nil && fn.Body != nil && strings.HasPrefix(fn.Name.Name, "Test")
			if isTestFn {
				c.tests = append(c.tests, fn.Name.Name)
			}
			if isTestFn && dir == "lab" && longMarkerUnitTests[fn.Name.Name] {
				continue
			}
			allowed := map[ast.Expr]bool{}
			if isTestFn && underLab {
				for _, st := range fn.Body.List {
					var exprs []ast.Expr
					switch st := st.(type) {
					case *ast.ExprStmt:
						exprs = []ast.Expr{st.X}
					case *ast.AssignStmt:
						exprs = st.Rhs
					}
					for _, e := range exprs {
						if call, ok := e.(*ast.CallExpr); ok && isMarker(call.Fun) {
							allowed[call.Fun] = true
						}
					}
				}
				if len(allowed) > 0 {
					c.callers = append(c.callers, fn.Name.Name)
				}
			}
			var walk func(n ast.Node) bool
			walk = func(n ast.Node) bool {
				e, ok := n.(ast.Expr)
				if !ok || !isMarker(e) {
					if sel, ok := n.(*ast.SelectorExpr); ok {
						ast.Inspect(sel.X, walk) // not Sel: x.LongTest is no marker for another x
						return false
					}
					return true
				}
				if !allowed[e] {
					why := "not a top-level test's own statement"
					switch {
					case !underLab:
						why = "outside lab/, where no stream runs it"
					case !isTest:
						why = "not in a test file"
					}
					c.misplaced = append(c.misplaced, fmt.Sprintf("%s:%d: %s: %s", rel, fset.Position(e.Pos()).Line, types.ExprString(e), why))
				}
				return false
			}
			if fn != nil {
				// fn.Name is a declaration, not a use: lab's own LongTest.
				if fn.Recv != nil {
					ast.Inspect(fn.Recv, walk)
				}
				ast.Inspect(fn.Type, walk)
				if fn.Body != nil {
					ast.Inspect(fn.Body, walk)
				}
			} else {
				ast.Inspect(decl, walk)
			}
		}
	}
	return c
}

// TestCheckLongMarkers: a marker call counts only as a top-level
// statement of a top-level test in a package under lab/, under any name
// lab is imported as; any other use is reported, and another package's
// LongTest is no marker.
func TestCheckLongMarkers(t *testing.T) {
	const imp = "import (\n\t\"testing\"\n\tlab \"example.net/m/lab\"\n)\n"
	for _, tc := range []struct {
		name, file, src string
		callers         []string
		misplaced       int
	}{
		{"top level", "lab/a_test.go", "package lab_test\n" + imp + "func TestA(t *testing.T) { t.Parallel(); lab.LongTest(t) }", []string{"TestA"}, 0},
		{"assigned, after an if", "lab/a_test.go", "package lab_test\n" + imp + "func TestA(t *testing.T) {\n\tif testing.Short() {\n\t\tt.Skip()\n\t}\n\ts := lab.SplitStreams(t)\n\t_ = s\n}", []string{"TestA"}, 0},
		{"alias", "lab/a_test.go", "package lab_test\nimport (\n\t\"testing\"\n\tl \"example.net/m/lab\"\n)\nfunc TestA(t *testing.T) { l.LongTest(t) }", []string{"TestA"}, 0},
		{"dot import", "lab/a_test.go", "package lab_test\nimport (\n\t\"testing\"\n\t. \"example.net/m/lab\"\n)\nfunc TestA(t *testing.T) { LongTest(t) }", []string{"TestA"}, 0},
		{"package lab", "lab/a_test.go", "package lab\nimport \"testing\"\nfunc TestA(t *testing.T) { LongTest(t) }", []string{"TestA"}, 0},
		{"a package under lab", "lab/ip/a_test.go", "package ip\n" + imp + "func TestA(t *testing.T) { lab.LongTest(t) }", []string{"TestA"}, 0},
		{"in a subtest", "lab/a_test.go", "package lab_test\n" + imp + "func TestA(t *testing.T) { t.Run(\"x\", func(t *testing.T) { lab.LongTest(t) }) }", nil, 1},
		{"alias in a subtest", "lab/a_test.go", "package lab_test\nimport (\n\t\"testing\"\n\tl \"example.net/m/lab\"\n)\nfunc TestA(t *testing.T) { t.Run(\"x\", func(t *testing.T) { l.LongTest(t) }) }", nil, 1},
		{"in an if", "lab/a_test.go", "package lab_test\n" + imp + "func TestA(t *testing.T) { if !testing.Short() { lab.LongTest(t) } }", nil, 1},
		{"in a helper", "lab/a_test.go", "package lab_test\n" + imp + "func slow(t *testing.T) { lab.LongTest(t) }\nfunc TestA(t *testing.T) { slow(t) }", nil, 1},
		{"as a value", "lab/a_test.go", "package lab_test\n" + imp + "func TestA(t *testing.T) { f := lab.LongTest; f(t) }", nil, 1},
		{"in a package var", "lab/a_test.go", "package lab_test\n" + imp + "var mark = lab.SplitStreams", nil, 1},
		{"outside lab", "internal/x/a_test.go", "package x\n" + imp + "func TestA(t *testing.T) { lab.LongTest(t) }", nil, 1},
		{"not a test file", "lab/a.go", "package lab\nimport \"testing\"\nfunc slow(t *testing.T) { LongTest(t) }", nil, 1},
		{"another package's LongTest", "lab/a_test.go", "package lab_test\nimport (\n\t\"testing\"\n\tlab \"example.net/m/other\"\n)\nfunc TestA(t *testing.T) { t.Run(\"x\", func(t *testing.T) { lab.LongTest(t) }) }", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, tc.file, tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			c := checkLongMarkers(fset, "example.net/m", map[string]*ast.File{tc.file: f})
			if !slices.Equal(c.callers, tc.callers) || len(c.misplaced) != tc.misplaced {
				t.Errorf("callers %q, misplaced %q; want callers %q, %d misplaced", c.callers, c.misplaced, tc.callers, tc.misplaced)
			}
		})
	}
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
