//go:build linux

package censor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestQueuePipeline runs the queue plumbing end to end in this node:
// nftables queues the node's own loopback output, the engine with block-ip
// decides, and the listener and the verdict log show what happened. It
// needs the lab: only there is nftables ours to command.
func TestQueuePipeline(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	tcpAddr := net.JoinHostPort("127.0.0.2", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: udp.LocalAddr().(*net.UDPAddr).Port}

	// startCensor serves a queue with one module behind an output-hook
	// rule — a router's forward hook never sees a node's own output, so
	// the test installs its own.
	startCensor := func(t *testing.T, table string, queue uint16, settings string) string {
		t.Helper()
		runNFT(t, fmt.Sprintf(`
table inet %s {
  chain out {
    type filter hook output priority filter; policy accept;
    queue num %d
  }
}
`, table, queue))
		t.Cleanup(func() { runNFT(t, "delete table inet "+table+"\n") })

		logPath := filepath.Join(t.TempDir(), "verdicts.jsonl")
		m, err := newBlockIP([]byte(settings))
		if err != nil {
			t.Fatal(err)
		}
		eng := NewEngine([]Passive{m}, nil, nil)
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- serveQueue(ctx, Config{Queue: queue, Log: logPath}, eng) }()
		t.Cleanup(func() {
			cancel()
			if err := <-errc; err != nil {
				t.Errorf("censor: %v", err)
			}
		})
		return logPath
	}
	t.Run("accepts what no module decides", func(t *testing.T) {
		startCensor(t, "censor-test-accept", 201, `{"destinations": ["203.0.113.9"]}`)
		c, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		got := make([]byte, 16)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			_, _ = c.Write([]byte("hello"))
			_ = udp.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, _, err := udp.ReadFromUDP(got); err == nil && string(got[:n]) == "hello" {
				return
			}
		}
		t.Fatal("the queued datagram never came back accepted")
	})

	t.Run("drops what a module drops", func(t *testing.T) {
		logPath := startCensor(t, "censor-test-drop", 202, `{"destinations": ["127.0.0.2"]}`)
		c, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		stop := time.Now().Add(2 * time.Second)
		for time.Now().Before(stop) {
			_, _ = c.Write([]byte("hello"))
			time.Sleep(100 * time.Millisecond)
		}
		// The verdict log, not silence alone, proves the pipeline
		// dropped the datagrams.
		if entry := verdictFor(t, logPath, func(e *LogEntry) bool {
			return e.Verdict == Drop && strings.Contains(e.Flow, "127.0.0.2")
		}); entry == nil {
			t.Fatal("no drop in the verdict log")
		}
	})

	t.Run("resets what a module resets", func(t *testing.T) {
		logPath := startCensor(t, "censor-test-reset", 203, `{"destinations": ["127.0.0.2"], "verdict": "reset"}`)
		// Every SYN to 127.0.0.2 gets an RST and is dropped, so the dial
		// fails; the log proves it was the censor's RST.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if conn, err := net.DialTimeout("tcp", tcpAddr, time.Second); err == nil {
				_ = conn.Close()
				continue
			}
			if entry := verdictFor(t, logPath, func(e *LogEntry) bool { return e.Verdict == Reset }); entry == nil {
				t.Fatal("no reset in the verdict log")
			}
			return
		}
		t.Fatal("a connection the censor reset still went through")
	})
}

// verdictFor reads the verdict log until an entry matches, briefly.
func verdictFor(t *testing.T, path string, match func(*LogEntry) bool) *LogEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if line == "" {
					continue
				}
				var e LogEntry
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatalf("verdict log line %q: %v", line, err)
				}
				if match(&e) {
					return &e
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func runNFT(t *testing.T, rule string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
}
