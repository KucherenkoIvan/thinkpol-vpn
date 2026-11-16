//go:build linux

package censor

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// TestReset: after Reset the node has no censor table and no conntrack
// entry, though a censor's queue rule and tracked flows were there. It
// needs the lab: only there are nftables and conntrack ours to command.
func TestReset(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	if err := installQueueRule(250); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeQueueRule)
	// The queue rule hooks forward, which a node's own datagrams never
	// cross: a table of the test's own tracks them.
	runNFT(t, `
table inet censor-test-ct {
  chain out {
    type filter hook output priority filter; policy accept;
    ct state new counter
  }
}
`)
	t.Cleanup(func() { runNFT(t, "delete table inet censor-test-ct\n") })
	for _, addr := range []string{"127.0.0.2:9", "[::1]:9"} {
		c, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("x"))
		_ = c.Close()
	}
	if n := conntrackCount(t); n == 0 {
		t.Fatal("no conntrack entry before the reset: the test tracks nothing")
	}

	if err := Reset(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput(); err == nil {
		t.Errorf("the censor's table outlived the reset:\n%s", out)
	}
	if n := conntrackCount(t); n != 0 {
		t.Errorf("%d conntrack entries after the reset, want none", n)
	}
}

func conntrackCount(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
