package lab

import (
	"context"
	_ "embed"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// CamouflageName is the lab's camouflage site's name, the one its
// certificate names first (it names CamouflageAltName too). The lab CA in
// the node image signs that certificate and every node trusts the CA, so
// the site verifies as a real one would.
const (
	CamouflageName    = "camouflage.example.net"
	CamouflageAltName = "www.example.net"
	CamouflagePort    = 443
)

// camouflageConf is the camouflage site's nginx configuration, a
// template of its temporary files' directory, its listen lines and its
// server names. A file, so a reality listener's test in a lab node, whose
// package may not import the lab, runs the same site.
//
//go:embed camouflage.nginx.conf
var camouflageConf string

// StartCamouflage runs the lab's camouflage site on Upstream's camouflage
// node: nginx as an ordinary HTTPS site, TLS 1.2 and 1.3 (nginx 1.22
// leaves 1.3 out unless told), HTTP/2 and HTTP/1.1, Debian's default page,
// with the image's certificate for CamouflageName, on CamouflagePort of
// both its addresses, unless it runs already. It returns them, IPv4
// first, once both listen. It is the target a reality listener splices
// to, and the site the prober and the server-hello comparison compare
// servers with.
func StartCamouflage(t testing.TB, l *Lab) []netip.AddrPort {
	t.Helper()
	node := l.Node(Camouflage)
	addrs := []netip.AddrPort{
		netip.AddrPortFrom(node.IPv4(NetWorld), CamouflagePort),
		netip.AddrPortFrom(node.IPv6(NetWorld), CamouflagePort),
	}
	const dir = "/tmp/camouflage"
	// A matrix row and its censor case may both start the site: the second
	// gets the running one.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	res, err := node.Exec(ctx, "test", "-e", dir+"/nginx.conf")
	cancel()
	switch {
	case err == nil:
		return addrs
	case res.ExitCode != 1:
		t.Fatalf("camouflage: %v", err)
	}
	var listen strings.Builder
	for _, a := range addrs {
		fmt.Fprintf(&listen, "    listen %s ssl http2;\n", a)
	}
	conf := fmt.Sprintf(camouflageConf, dir, listen.String(), CamouflageName+" "+CamouflageAltName)
	node.WriteFile(t, dir+"/nginx.conf", []byte(conf))
	node.Start(t, "nginx", "-c", dir+"/nginx.conf", "-g", "daemon off;")
	Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, a := range addrs {
			if _, err := node.Exec(ctx, "nc", "-z", "-w", "2", a.Addr().String(), fmt.Sprint(a.Port())); err != nil {
				return fmt.Errorf("the camouflage site isn't listening on %s: %v", a, err)
			}
		}
		return nil
	})
	return addrs
}
