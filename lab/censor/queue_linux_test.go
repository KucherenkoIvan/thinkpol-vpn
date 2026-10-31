//go:build linux

package censor

import (
	"bytes"
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
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
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
		// The log file, as censord's main opens it and hands it to the
		// engine.
		logFile, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = logFile.Close() })
		m, err := newBlockIP([]byte(settings))
		if err != nil {
			t.Fatal(err)
		}
		eng := NewEngine([]Passive{m}, nil, logFile)
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- serveQueue(ctx, Config{Queue: queue}, eng) }()
		t.Cleanup(func() {
			cancel()
			if err := <-errc; err != nil {
				t.Errorf("censor: %v", err)
			}
			eng.Shutdown() // as Run does: once the queue has stopped calling Handle
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

	// A throttled flow is policed: a burst far past the rate loses most
	// of its datagrams at once, where a hold would deliver them all late.
	// The bucket holds two datagrams and refills one every half second,
	// so under half get through unless sending forty takes nine seconds.
	t.Run("polices what a module throttles", func(t *testing.T) {
		logPath := startCensor(t, "censor-test-throttle", 203,
			`{"destinations": ["127.0.0.2"], "verdict": "throttle", "rate": 1000, "burst": 1000}`)
		c, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		drain(udp) // the accept case may have left extra hellos
		const sent = 40
		datagram := make([]byte, 500)
		for i := 0; i < sent; i++ {
			if _, err := c.Write(datagram); err != nil {
				t.Fatal(err)
			}
		}
		got := 0
		buf := make([]byte, 1024)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := udp.ReadFromUDP(buf); err != nil {
				break
			}
			got++
		}
		if got < 2 || got >= sent/2 {
			t.Errorf("%d of %d datagrams crossed a 1000 B/s throttle, want the burst's 2 and few more", got, sent)
		}
		if entry := verdictFor(t, logPath, func(e *LogEntry) bool {
			return e.Verdict == Throttle && e.Rate == 1000 && strings.Contains(e.Flow, "127.0.0.2")
		}); entry == nil {
			t.Fatal("no throttle in the verdict log")
		}
	})

}

// drain discards what waits on the socket.
func drain(c *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, _, err := c.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

// verdictFor reads the verdict log until an entry matches, briefly.
func verdictFor(t *testing.T, path string, match func(*LogEntry) bool) *LogEntry {
	t.Helper()
	e, err := pollVerdicts(path, match)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func pollVerdicts(path string, match func(*LogEntry) bool) (*LogEntry, error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			// Up to the last newline: the rest is a write in progress.
			whole := string(b[:bytes.LastIndexByte(b, '\n')+1])
			for _, line := range strings.Split(whole, "\n") {
				if line == "" {
					continue
				}
				var e LogEntry
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					return nil, fmt.Errorf("verdict log line %q: %w", line, err)
				}
				if match(&e) {
					return &e, nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, nil
}

func runNFT(t *testing.T, rule string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s", err, out)
	}
}
