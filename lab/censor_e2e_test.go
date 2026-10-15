//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

const tcpProbePort = 18080

// TestTCPResetNotOnServer checks block-ip reset: the client sees a reset,
// and the RST is injected toward the client, not forwarded to server-1.
func TestTCPResetNotOnServer(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	server := l.Node(lab.Server1)
	underlay4, underlay6 := bringUpM0TCP(t, l)
	_, qd0, ud0 := startCensor(t, l, entryBlockSettings(t, l, "reset"))
	cap := server.Start(t, "tcpdump", "-i", "any", "-nn", "-l", "tcp", "and", "port", fmt.Sprint(tcpProbePort))
	time.Sleep(500 * time.Millisecond)

	tryTCP(t, l.Node(lab.DeviceA), underlay4, false)
	tryTCP(t, l.Node(lab.DeviceA), underlay6, false)

	time.Sleep(500 * time.Millisecond)
	out := cap.Output()
	if strings.Contains(out, " Flags [R") || strings.Contains(out, " Flags [R.") {
		t.Errorf("server-1 saw an RST on the wire:\n%s", out)
	}
	assertCensorSaw(t, l, server.IPv4(lab.NetServers), qd0, ud0)
}

// TestTCPThroughCensorDrop checks TCP across the router with block-ip drop.
func TestTCPThroughCensorDrop(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	server := l.Node(lab.Server1)
	underlay4, underlay6 := bringUpM0TCP(t, l)
	_, qd0, ud0 := startCensor(t, l, entryBlockSettings(t, l, "drop"))
	tryTCP(t, l.Node(lab.DeviceA), underlay4, false)
	tryTCP(t, l.Node(lab.DeviceA), underlay6, false)
	assertCensorSaw(t, l, server.IPv4(lab.NetServers), qd0, ud0)
}

// TestFragmentedUDPDropped ensures non-first IPv4 fragments never pass as
// accepted payloads through the censor.
func TestFragmentedUDPDropped(t *testing.T) {
	l := lab.Start(t, lab.Standard())
	_, _ = bringUpM0TCP(t, l)
	startCensor(t, l, []censor.ModuleConfig{})
	router := l.Node(lab.Router)
	serverIP := l.Node(lab.Server1).IPv4(lab.NetServers).String()
	iface := router.Interface(lab.NetServers)
	router.MustExec(t, "sh", "-ec", fmt.Sprintf("ip link set dev %s mtu 576", iface))
	_, err := router.Exec(context.Background(), "which", "hping3")
	if err != nil {
		t.Skip("hping3 not in the lab image")
	}
	router.MustExec(t, "sh", "-ec", fmt.Sprintf("hping3 -2 -c 1 -d 1200 -p 54321 --frag %s >/dev/null 2>&1", serverIP))
	time.Sleep(time.Second)
	log := router.MustExec(t, "cat", "/run/censor/verdicts.jsonl")
	for _, line := range strings.Split(log, "\n") {
		if line == "" {
			continue
		}
		var e censor.LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Verdict == censor.Accept && strings.Contains(e.Flow, ":54321") {
			t.Errorf("fragmented flow accepted: %s", line)
		}
	}
}

func entryBlockSettings(t *testing.T, l *lab.Lab, verdict string) []censor.ModuleConfig {
	server := l.Node(lab.Server1)
	s := struct {
		Destinations []string `json:"destinations"`
		Verdict      string   `json:"verdict,omitempty"`
	}{Destinations: []string{
		server.IPv4(lab.NetServers).String(),
		server.IPv6(lab.NetServers).String(),
	}, Verdict: verdict}
	if verdict == "drop" {
		s.Verdict = ""
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return []censor.ModuleConfig{{Name: "block-ip", Settings: b}}
}

func bringUpM0TCP(t *testing.T, l *lab.Lab) (netip.Addr, netip.Addr) {
	t.Helper()
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	upDev := dev.Start(t, "thinkpol", "up")
	upSrv := server.Start(t, "thinkpol", "up")
	applied := applied(version)
	if err := waitOutput(upSrv, applied, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitOutput(upDev, applied, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitOutput(upDev, `link up`, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	u4, u6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)
	server.Start(t, "sh", "-ec", fmt.Sprintf(
		"nc -4 -l -p %d -s %s >/dev/null 2>&1 & nc -6 -l -p %d -s %s >/dev/null 2>&1 &",
		tcpProbePort, u4, tcpProbePort, u6))
	lab.Eventually(t, 60*time.Second, func() error {
		out := server.MustExec(t, "sh", "-ec", fmt.Sprintf("ss -H -lnt sport = :%d | wc -l", tcpProbePort))
		n := strings.TrimSpace(out)
		if n == "0" || n == "" {
			return fmt.Errorf("listeners: %q", out)
		}
		return nil
	})
	return u4, u6
}

func tryTCP(t *testing.T, dev *lab.Node, dst netip.Addr, wantOK bool) {
	t.Helper()
	err := tcpConnect(dev, dst)
	if wantOK && err != nil {
		t.Errorf("tcp to %s: %v", dst, err)
	}
	if !wantOK && err == nil {
		t.Errorf("tcp to %s connected, want failure", dst)
	}
}

func tcpConnect(dev *lab.Node, dst netip.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := dev.Exec(ctx, "sh", "-ec", fmt.Sprintf("nc -z -w 3 %s %d", dst, tcpProbePort))
	return err
}

func assertCensorSaw(t *testing.T, l *lab.Lab, server netip.Addr, qd0, ud0 uint64) {
	t.Helper()
	if err := censorHealthSince(t, l, qd0, ud0); err != nil {
		t.Fatal(err)
	}
	router := l.Node(lab.Router)
	out := router.MustExec(t, "cat", "/run/censor/verdicts.jsonl")
	if out == "" {
		t.Fatal("empty verdict log")
	}
	want := []netip.Addr{server, l.Node(lab.Server1).IPv6(lab.NetServers)}
	found := false
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		var e censor.LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("verdict: %v", err)
		}
		key, err := censor.ParseFlowKey(e.Flow)
		if err != nil {
			continue
		}
		for _, d := range want {
			if key.Dst == d && e.Module == "block-ip" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("verdict log has no block-ip flow to %v:\n%s", want, out)
	}
}
