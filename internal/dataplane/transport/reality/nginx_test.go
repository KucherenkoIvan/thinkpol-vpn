package reality

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	transportv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/transport/v1"
)

// The lab image's camouflage site: nginx with the certificate the lab CA
// signed (lab.StartCamouflage runs the same on the camouflage node).
const (
	labSiteName = "camouflage.example.net"
	labSiteCert = "/etc/lab/camouflage/cert.pem"
	labSiteKey  = "/etc/lab/camouflage/key.pem"
)

// startLabSite runs the lab's camouflage site on a loopback port of this
// node, as lab.StartCamouflage configures it, and returns its address.
func startLabSite(t *testing.T) string {
	t.Helper()
	nginx, err := exec.LookPath("nginx")
	if err != nil {
		nginx = "/usr/sbin/nginx"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	dir := t.TempDir()
	conf := fmt.Sprintf(`worker_processes 1;
pid %[1]s/nginx.pid;
error_log stderr;
events {}
http {
  access_log off;
  client_body_temp_path %[1]s;
  proxy_temp_path %[1]s;
  fastcgi_temp_path %[1]s;
  uwsgi_temp_path %[1]s;
  scgi_temp_path %[1]s;
  server {
    listen %[2]s ssl http2;
    server_name %[3]s;
    ssl_certificate %[4]s;
    ssl_certificate_key %[5]s;
    ssl_protocols TLSv1.2 TLSv1.3;
    root /var/www/html;
    index index.html index.nginx-debian.html;
  }
}
`, dir, addr, labSiteName, labSiteCert, labSiteKey)
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(nginx, "-c", path, "-g", "daemon off;")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("nginx isn't listening on %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The lab's camouflage site, nginx, and a listener in front of it react
// alike to the prober's random probes of 1000 bytes and to writes after
// the site's FIN: the same write fails, or none.
func TestAfterTheLabSitesFINTheSameWriteFails(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	if _, err := os.Stat(labSiteCert); err != nil {
		t.Skipf("no lab camouflage certificate: %v", err)
	}
	site := startLabSite(t)
	k := newKeys(t)
	settings := mustMarshal(t, &transportv1.RealityListenSettings{PrivateKey: k.private, Target: site, ServerNames: []string{labSiteName}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l, err := New(Options{}).Listen(ctx, transport.ListenConfig{Address: "127.0.0.1:0", Settings: settings}, transport.Admission{Peers: transport.NewPeerTable()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for name, what := range probesAfterTheFIN() {
		t.Run(name, func(t *testing.T) {
			direct := afterTheFIN(t, site, what)
			through := afterTheFIN(t, l.Addr().String(), what)
			t.Logf("nginx: %s; through the listener: %s", direct, through)
			if through != direct {
				t.Errorf("through the listener: %s; nginx: %s", through, direct)
			}
		})
	}
}
