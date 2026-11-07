//go:build lab

package lab_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Stock Xray, the REALITY server reality's dialer must interoperate with:
// pinned by the multi-arch index digest of the release tag. The lab never
// reaches the internet: the camouflage target is a site in the lab node,
// and the image is the only thing fetched from outside, before the test's
// traffic starts (once, when the host doesn't have it yet).
const (
	xrayTag    = "26.3.27"
	xrayRef    = "ghcr.io/xtls/xray-core@sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7"
	xrayPort   = 443
	xrayTarget = 8443
	// xraySNI is the reality package's test server name, which its target
	// serves.
	xraySNI = "www.example.net"
)

// TestRealityStockXray runs the reality package's TestStockXray in a lab
// node against stock Xray: the right short id verifies (Xray's certificate
// proves its key), and a wrong one is spliced, raw and whole, to the
// target site the test runs in the node.
func TestRealityStockXray(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Topology{
		Networks: []lab.Network{{Name: "reality", IPv4Only: true}},
		Nodes:    []lab.NodeSpec{{Name: "client", Networks: []string{"reality"}}},
	})
	node := l.Node("client")

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := make([]byte, 8)
	if _, err := rand.Read(shortID); err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("%s:%d", node.IPv4("reality"), xrayTarget)
	name := startXray(t, l, "reality", key.Bytes(), shortID, target)
	xrayAddr := fmt.Sprintf("%s:%d", containerIPv4(t, name), xrayPort)

	config, err := json.Marshal(map[string]any{
		"server": xrayAddr, "target": target, "public_key": key.PublicKey().Bytes(), "short_id": shortID,
	})
	if err != nil {
		t.Fatal(err)
	}
	node.WriteFile(t, "/run/reality-xray/config.json", config)
	lab.Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := node.Exec(ctx, "nc", "-z", containerIPv4(t, name), fmt.Sprint(xrayPort)); err != nil {
			return fmt.Errorf("xray isn't listening: %v\n%s", err, containerLogs(name))
		}
		return nil
	})

	root, err := lab.Root()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	pkgs, err := lab.ListGoPackages(ctx, root, "./internal/dataplane/transport/reality")
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("the reality package: %v %v", pkgs, err)
	}
	var out bytes.Buffer
	if err := node.GoTest(ctx, &out, pkgs[0], "-test.v", "-test.run", "^TestStockXray$"); err != nil {
		t.Fatalf("in the node:\n%s\nxray %s:\n%s", out.String(), xrayTag, containerLogs(name))
	}
	// A skip is not a failure: only both subtests passing shows the check
	// ran.
	for _, sub := range []string{"right_short_id", "wrong_short_id"} {
		if !strings.Contains(out.String(), "--- PASS: TestStockXray/"+sub) {
			t.Errorf("no pass for %s in the node's output:\n%s", sub, out.String())
		}
	}
}

// startXray runs stock Xray on the lab network as a REALITY inbound
// accepting shortID, with target as its camouflage target, and returns its
// container's name. It carries the lab's labels, so the lab's teardown and
// make lab-down remove it like any lab container.
func startXray(t *testing.T, l *lab.Lab, network string, privateKey, shortID []byte, target string) string {
	t.Helper()
	root, err := lab.Root()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "lab", ".run", l.Project)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "0.0.0.0", "port": xrayPort, "protocol": "vless",
			"settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": "2ca97d98-6d25-4de2-8a30-2b90cc0100ea"}}},
			"streamSettings": map[string]any{
				"network": "raw", "security": "reality",
				"realitySettings": map[string]any{
					"target":      target,
					"serverNames": []string{xraySNI},
					"privateKey":  base64.RawURLEncoding.EncodeToString(privateKey),
					"shortIds":    []string{hex.EncodeToString(shortID)},
					// Milliseconds: five minutes, reality's own default.
					"maxTimeDiff": 300000,
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "blackhole"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "xray-reality.json")
	if err := os.WriteFile(confPath, conf, 0o644); err != nil {
		t.Fatal(err)
	}
	name := l.Project + "-xray-reality"
	out, err := exec.Command("docker", "run", "-d", "--name", name,
		"--label", "org.thinkpol.lab=1",
		"--label", "org.thinkpol.lab.root="+root,
		"--label", "com.docker.compose.project="+l.Project,
		"--network", l.Project+"_"+network,
		"--volume", confPath+":/usr/local/etc/xray/config.json:ro",
		xrayRef, "run", "-c", "/usr/local/etc/xray/config.json").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run xray: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	return name
}

func containerIPv4(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", name, "--format",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}").Output()
	if err != nil {
		t.Fatalf("docker inspect %s: %v", name, err)
	}
	return strings.TrimSpace(string(out))
}

// containerLogs is a container's log, read with a bound.
func containerLogs(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "logs", name).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("(no logs: %v)", err)
	}
	return string(out)
}
