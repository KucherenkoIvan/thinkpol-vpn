package lab

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// harnessTestFiles names the test files make lab-test's harness phase
// hashes (LAB_HARNESS_FILES in the Makefile), beside every non-test file
// under lab/.
const harnessTestFiles = "harness*_test.go"

// The harness phase reruns only when its hash changes, so everything a
// TestHarness test runs must be in a hashed file: a helper elsewhere could
// change and weaken the test without rerunning it. This follows the
// declarations the TestHarness tests, TestMain and test files' init
// functions name, through package lab and its external tests, and fails on
// any declared in a test file the hash leaves out. A type reached brings
// all its methods, wherever declared. It over-approximates (a local
// shadowing a package-level name counts as that name): a false hit moves a
// declaration into a hashed file, which only reruns the harness more often.
func TestTheHarnessHashCoversWhatItsTestsReach(t *testing.T) {
	makefile, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(makefile, []byte("$(wildcard lab/"+harnessTestFiles+")")) {
		t.Fatalf("the Makefile's harness hash doesn't cover lab/%s", harnessTestFiles)
	}
	unhashed, err := harnessReachesUnhashed(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range unhashed {
		t.Errorf("%s: move it into a lab/%s file", u, harnessTestFiles)
	}
}

// declKey names a package-level declaration of package pkg; a method is
// filed under its receiver's type.
type declKey struct{ pkg, name string }

// harnessReachesUnhashed lists the declarations in dir's test files outside
// harnessTestFiles that the harness's tests reach.
func harnessReachesUnhashed(dir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	type decl struct {
		file string
		node ast.Node
	}
	decls := map[declKey][]decl{}
	var roots []declKey
	fset := token.NewFileSet()
	for _, path := range paths {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		pkg, file := f.Name.Name, filepath.Base(path)
		add := func(name string, n ast.Node) {
			decls[declKey{pkg, name}] = append(decls[declKey{pkg, name}], decl{file, n})
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					add(receiverType(d.Recv.List[0].Type), d)
					continue
				}
				add(d.Name.Name, d)
				name := d.Name.Name
				if strings.HasSuffix(file, "_test.go") && (strings.HasPrefix(name, "TestHarness") || name == "TestMain" || name == "init") {
					roots = append(roots, declKey{pkg, name})
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							add(n.Name, s)
						}
					case *ast.TypeSpec:
						add(s.Name.Name, s)
					}
				}
			}
		}
	}

	from := map[declKey]declKey{}
	seen := map[declKey]bool{}
	var unhashed []string
	var visit func(k declKey)
	visit = func(k declKey) {
		if seen[k] {
			return
		}
		seen[k] = true
		reach := func(r declKey) {
			if _, ok := decls[r]; ok && !seen[r] {
				if _, ok := from[r]; !ok {
					from[r] = k
				}
				visit(r)
			}
		}
		for _, d := range decls[k] {
			if hashed, _ := filepath.Match(harnessTestFiles, d.file); strings.HasSuffix(d.file, "_test.go") && !hashed {
				name := k.name
				if f, ok := d.node.(*ast.FuncDecl); ok && f.Recv != nil {
					name += "." + f.Name.Name
				}
				unhashed = append(unhashed, fmt.Sprintf("%s (%s) is reached by %s", name, d.file, harnessPath(from, k)))
			}
			var inspect func(n ast.Node) bool
			inspect = func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					if x, ok := n.X.(*ast.Ident); ok && k.pkg == "lab_test" && x.Name == "lab" {
						reach(declKey{"lab", n.Sel.Name})
						return false
					}
					// A method or field: reached with its type.
					ast.Inspect(n.X, inspect)
					return false
				case *ast.Ident:
					reach(declKey{k.pkg, n.Name})
				}
				return true
			}
			ast.Inspect(d.node, inspect)
		}
	}
	for _, r := range roots {
		visit(r)
	}
	slices.Sort(unhashed)
	return slices.Compact(unhashed), nil
}

// harnessPath is the chain of declarations from a root to k.
func harnessPath(from map[declKey]declKey, k declKey) string {
	chain := []string{k.name}
	for {
		p, ok := from[k]
		if !ok {
			break
		}
		chain = append(chain, p.name)
		k = p
	}
	slices.Reverse(chain)
	return strings.Join(chain, " → ")
}

// receiverType is the name of a method receiver's type: T of T, *T, T[P].
func receiverType(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}
