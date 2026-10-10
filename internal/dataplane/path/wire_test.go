package path_test

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// TestFramesOnTheLink speaks the path layer's frame format by hand to a
// relay, as an adjacent node would.
func TestFramesOnTheLink(t *testing.T) {
	f := newFabric(t, 0)
	f.add("R", "B")
	f.dial("B", "R")
	f.route("R", "B", "B")
	r := f.node("R")
	secret := []byte("raw X>R")
	r.inbound = append(r.inbound, transport.PeerLink{Peer: transport.Identity{Node: id("X")}, Verifier: secret})
	r.peers.Set(r.inbound)
	// The listener takes up a table change on its own time: redial until
	// a probe is answered, as the path layer does.
	probe := []byte{2, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	var l transport.Link
	eventually(t, "R answers a probe", func() bool {
		try, err := f.tr.Dial(context.Background(), "R", transport.DialConfig{Credential: secret})
		if err != nil {
			t.Fatal(err)
		}
		l = try
		if err := try.WritePacket(probe); err != nil {
			t.Fatal(err)
		}
		reply := make(chan []byte, 1)
		go func() {
			buf := make([]byte, transport.MaxPacketSize)
			n, _ := try.ReadPacket(buf)
			reply <- buf[:n]
		}()
		select {
		case got := <-reply:
			if want := append([]byte{3}, probe[1:]...); !bytes.Equal(got, want) {
				t.Fatalf("probe answered with %x, want %x", got, want)
			}
			return true
		case <-time.After(50 * time.Millisecond):
			_ = try.Close()
			return false
		}
	})
	defer func() { _ = l.Close() }()

	b, x := id("B"), id("X")
	packet := func(hops byte, dst [8]byte) []byte {
		return append(append(append([]byte{1, hops}, dst[:]...), x[:]...), "wg"...)
	}
	for _, frame := range [][]byte{
		{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // unknown kind
		packet(0, b),                      // no hops left
		packet(5, b)[:18],                 // no message
		packet(1, b),                      // would reach B with none left
	} {
		if err := l.WritePacket(frame); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "R drops all four", func() bool {
		c := r.Counters()
		return c.Malformed == 3 && c.HopLimit == 1
	})

	if err := l.WritePacket(packet(2, b)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "R forwards to B", func() bool { return r.Counters().Forwarded == 1 })
	eventually(t, "B gets it from X, a stranger", func() bool { return f.node("B").Counters().UnknownPeer == 1 })
}

// TestNoSocketsInThePathLayer: the path layer, WireGuard's only Bind, never
// opens a socket of its own. Everything leaves through transport links.
func TestNoSocketsInThePathLayer(t *testing.T) {
	forbidden := map[string][]string{
		"net":                             {"Dial", "DialUDP", "DialTCP", "DialIP", "DialUnix", "DialTimeout", "Listen", "ListenUDP", "ListenTCP", "ListenIP", "ListenPacket", "ListenUnix", "ListenUnixgram", "ListenMulticastUDP", "FileConn", "FilePacketConn"},
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
					t.Errorf("%s: %s.%s opens a socket", fset.Position(sel.Pos()), pkg.Name, fn)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no source files checked")
	}
}
