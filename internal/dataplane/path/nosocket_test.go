package path_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoSocketsInThePathLayer: the path layer, WireGuard's only Bind, never
// opens a socket of its own. Everything leaves through transport links.
func TestNoSocketsInThePathLayer(t *testing.T) {
	forbidden := map[string][]string{
		"net": {"Dial", "DialUDP", "DialTCP", "DialIP", "DialUnix", "DialTimeout", "Listen", "ListenUDP", "ListenTCP", "ListenIP", "ListenPacket", "ListenUnix", "ListenUnixgram", "ListenMulticastUDP", "FileConn", "FilePacketConn",
			"Dialer", "ListenConfig", "UDPConn", "TCPConn", "IPConn", "UnixConn"},
		"golang.zx2c4.com/wireguard/conn": {"NewDefaultBind", "NewStdNetBind"},
	}
	banned := []string{"syscall", "golang.org/x/sys/unix", "golang.org/x/sys/windows"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		local := map[string]string{} // import name → path
		for _, imp := range file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, b := range banned {
				if p == b {
					t.Errorf("%s imports %s", name, p)
				}
			}
			n := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				n = imp.Name.Name
			}
			local[n] = p
		}
		ast.Inspect(file, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			for _, fn := range forbidden[local[pkg.Name]] {
				if sel.Sel.Name == fn {
					t.Errorf("%s: %s.%s is a socket", fset.Position(sel.Pos()), pkg.Name, fn)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}
