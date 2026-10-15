//go:build lab

// The TP-064 prototype driver: a stock Xray container (image pinned by
// digest) as the REALITY server, and one lab node carrying the
// thinkpol-written client, the camouflage target and the echo server. The
// image pull is the only thing that touches the network outside the lab;
// the client's traffic never leaves it.
package reality_test

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

// The stock server: the only part of this lab we don't build. Pinned by the
// multi-arch index digest of the tag (docker buildx imagetools inspect);
// the tag is recorded for the ticket.
const (
	xrayImage  = "ghcr.io/xtls/xray-core"
	xrayTag    = "26.3.27"
	xrayDigest = "sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7"
	xrayRef    = xrayImage + "@" + xrayDigest

	sni        = "example.net"
	realityNet = "reality"
	clientNode = "client"
	xrayName   = "xray"
	xrayPort   = 443
	targetPort = 8443
	echoPort   = 8001
	// maxTimeDiff is 10000. Xray's conf multiplies it by time.Millisecond,
	// so the window is 10 s; read as seconds it would be ~2.8 h. The stale
	// timestamp subtest in the node (60 s skew, right short id, splice
	// expected) fails if the server reads it as seconds.
	maxTimeDiff = 10000
)

func TestRealityPrototype(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Topology{
		Networks: []lab.Network{{Name: realityNet, IPv4Only: true}},
		Nodes:    []lab.NodeSpec{{Name: clientNode, Networks: []string{realityNet}}},
	})
	node := l.Node(clientNode)

	serverKey := make([]byte, 32)
	if _, err := rand.Read(serverKey); err != nil {
		t.Fatal(err)
	}
	serverPriv, err := ecdh.X25519().NewPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPubB64 := base64.RawURLEncoding.EncodeToString(serverPriv.PublicKey().Bytes())
	shortID := shortID8(t)
	shortIDWrong := shortID8(t)
	userID := "2ca97d98-6d25-4de2-8a30-2b90cc0100ea"

	nodeAddr := node.IPv4(realityNet).String()
	xrayIP := startXray(t, l, node, serverKey, shortID, userID, nodeAddr)

	config, err := json.Marshal(map[string]string{
		"xray_addr":       fmt.Sprintf("%s:%d", xrayIP, xrayPort),
		"sni":             sni,
		"server_key":      serverPubB64,
		"short_id":        shortID,
		"short_id_wrong":  shortIDWrong,
		"user_id":         userID,
		"http_addr":       fmt.Sprintf("%s:%d", nodeAddr, echoPort),
		"xray_version":    xrayTag,
		"target_tls_addr": fmt.Sprintf("%s:%d", nodeAddr, targetPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	node.WriteFile(t, "/run/reality-prototype/config.json", config)

	lab.Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := node.Exec(ctx, "nc", "-z", xrayIP, fmt.Sprint(xrayPort)); err != nil {
			return fmt.Errorf("xray %s:%d not answering: %v\n%s", xrayIP, xrayPort, err, xrayLogs(t, l))
		}
		return nil
	})

	// The in-node tests skip (and a skip is not a failure) when the lab env
	// or the config is missing, so a green run proves nothing unless the
	// output shows every subtest passing.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	pkgs, err := lab.ListGoPackages(ctx, mustRoot(t), "./lab/prototypes/reality")
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		var out bytes.Buffer
		if err := node.GoTest(ctx, &out, pkg, "-test.v", "-test.run", "TestRealityClientInterop"); err != nil {
			t.Errorf("in-node tests failed:\n%s\n%s", out.String(), xrayLogs(t, l))
			continue
		}
		t.Logf("in-node tests:\n%s", out.String())
		for _, subtest := range []string{"right_short_id", "wrong_short_id", "stale_timestamp"} {
			want := "--- PASS: TestRealityClientInterop/" + subtest
			if !strings.Contains(out.String(), want) {
				t.Errorf("in-node output has no %q (skipped?):\n%s", want, out.String())
			}
		}
	}
}

func mustRoot(t *testing.T) string {
	t.Helper()
	root, err := lab.Root()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// shortID8 returns a random short id, hex-encoded: the credential's wire
// form in the Xray config.
func shortID8(t *testing.T) string {
	t.Helper()
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(id)
}

// startXray runs the stock Xray container on the lab network, wired as a
// VLESS-over-REALITY inbound whose camouflage target is the node's TLS
// server. It carries the lab's labels, so the harness's teardown and
// make lab-down clean it up like any compose container.
func startXray(t *testing.T, l *lab.Lab, node *lab.Node, serverKey []byte, shortID, userID, nodeAddr string) string {
	t.Helper()
	root, err := lab.Root()
	if err != nil {
		t.Fatal(err)
	}
	confDir := filepath.Join(root, "lab", ".run", l.Project)
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   "0.0.0.0",
			"port":     xrayPort,
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients":    []any{map[string]any{"id": userID}},
			},
			"streamSettings": map[string]any{
				"network":  "raw",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        true,
					"target":      fmt.Sprintf("%s:%d", nodeAddr, targetPort),
					"xver":        0,
					"serverNames": []string{sni},
					"privateKey":  base64.RawURLEncoding.EncodeToString(serverKey),
					"shortIds":    []string{shortID},
					"maxTimeDiff": maxTimeDiff,
				},
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	raw, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(confDir, "xray.json")
	if err := os.WriteFile(confPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	name := l.Project + "-" + xrayName
	args := []string{
		"run", "-d", "--name", name,
		"--label", "org.thinkpol.lab=1",
		"--label", "org.thinkpol.lab.root=" + root,
		"--label", "com.docker.compose.project=" + l.Project,
		"--network", l.Project + "_" + realityNet,
		"--volume", confPath + ":/usr/local/etc/xray/config.json:ro",
		xrayRef,
		"run", "-c", "/usr/local/etc/xray/config.json",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run xray: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	res, err := exec.Command("docker", "inspect", name, "--format",
		"{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}").Output()
	if err != nil {
		t.Fatalf("inspect xray: %v", err)
	}
	return strings.TrimSpace(string(res))
}

func xrayLogs(t *testing.T, l *lab.Lab) string {
	t.Helper()
	out, err := exec.Command("docker", "logs", l.Project+"-"+xrayName).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("(no xray logs: %v)", err)
	}
	return string(out)
}
