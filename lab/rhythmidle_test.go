//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// idleRhythmHold is how long the idle rhythm case holds its tunnels idle:
// at real time whatever the lab's WireGuard timer scale, since idle path
// probes keep real time. Long enough for reality's draws (one exchange per
// 13.3 s on average) to make the sixteen exchanges the steady signal needs
// (18 on average), udp's (one per 8 s) nearly twice over, and for the
// pinger (6 s apart) to be caught at about 100 s. The chance that udp's
// draws show the signal in it is about 10⁻⁸ (some 16 runs of fifteen
// intervals, each 5.7·10⁻¹⁰, lab/censor/doc.go), reality's about 10⁻¹².
const idleRhythmHold = 4 * time.Minute

// rhythmIdleCase is the wireguard-rhythm case that holds the held rows'
// tunnels idle after one ping: an idle thinkpol tunnel carries no
// WireGuard rhythm (lab/censor/doc.go, "keepalive"), only its path
// probes, so reality and udp must pass; the https row holds a TLS pinger
// (holdPinger), which the steady signal must catch. The module keeps
// real time (no rekey setting): idle, the lab's sped-up WireGuard runs
// none of its timers past the first passive keepalive, and the path
// probes keep real time, so a scaled rekey period would read their
// exchanges, each after the scaled quiet, as rekeys 12 s apart.
func rhythmIdleCase() censorCase {
	b, err := json.Marshal(map[string]string{"trace": rhythmTrace})
	if err != nil {
		panic(err)
	}
	return censorCase{name: "wireguard-rhythm (idle)", hold: idleRhythmHold, idle: true, watch: "wireguard-rhythm", trace: rhythmTrace,
		expect: map[string]string{rowHTTPS: "fail"}, blocker: "wireguard-rhythm",
		failFor: map[string]string{rowHTTPS: censor.WGRhythmBySteady},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
			return []censor.ModuleConfig{{Name: "wireguard-rhythm", Settings: b}}
		}}
}

// pingerPort is the pinger's TLS echo server's port on server-1.
const pingerPort = 8443

// pingerEvery is the pinger's fixed interval: longer than the module's
// quiet at real time (REKEY_TIMEOUT), so each exchange comes after quiet.
const pingerEvery = 6 * time.Second

// holdPinger holds the https row idle for d: a lab-only TLS pinger,
// device-a sending one fixed record ("ping") to a TLS echo server on
// server-1 every pingerEvery and getting it back, nothing else on the
// connection, started after censord so the module reads it from its
// first byte. It never holds in use (transport.idleOnly). The pinger
// must have exchanged at least the records each way the steady signal
// needs before the censor could cut it, or the hold held nothing.
func holdPinger(t *testing.T, l *lab.Lab, to probeTarget, d time.Duration, idle bool, blocks func() int) {
	if !idle {
		t.Fatal("the pinger holds only idle")
	}
	server, dev := l.Node(lab.Server1), l.Node(lab.DeviceA)
	server.Start(t, "socat", fmt.Sprintf("OPENSSL-LISTEN:%d,reuseaddr,fork,verify=0,cert=/etc/lab/camouflage/cert.pem,key=/etc/lab/camouflage/key.pem", pingerPort), "EXEC:cat")
	lab.Eventually(t, 10*time.Second, func() error {
		out, err := execRead(server, pollTimeout, "ss", "-Htln", fmt.Sprintf("sport = :%d", pingerPort))
		if err != nil || strings.TrimSpace(out) == "" {
			return fmt.Errorf("the pinger's echo server isn't listening yet (%v)", err)
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), d+time.Minute)
	defer cancel()
	loop := fmt.Sprintf("while :; do echo ping; sleep %d; done", int(pingerEvery/time.Second))
	res, _ := dev.Exec(ctx, "timeout", strconv.Itoa(int(d/time.Second)), "sh", "-c",
		loop+" | socat -T 30 - OPENSSL:"+to.v4.String()+":"+strconv.Itoa(pingerPort)+",verify=0")
	echoes := strings.Count(res.Stdout, "ping\n")
	if want := censor.WGRhythmSteadyExchanges + 1; echoes < want {
		t.Fatalf("the pinger got %d echoes in %v, want at least %d (the steady signal's %d and the one that judges them): %s", echoes, d, want, censor.WGRhythmSteadyExchanges, res.Stderr)
	}
	t.Logf("the pinger's hold: %d echoes, %d blocks", echoes, blocks())
}

// pingerFlow matches the pinger's connection from device-a to server-1.
func pingerFlow(l *lab.Lab, k censor.FlowKey) bool {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	return k.Proto == censor.ProtoTCP && k.DstPort == pingerPort &&
		(k.Src == dev.IPv4(lab.NetDevices) && k.Dst == server.IPv4(lab.NetServers) ||
			k.Src == dev.IPv6(lab.NetDevices) && k.Dst == server.IPv6(lab.NetServers))
}

// failedFor checks that blocker blocked for why, a block reason's start,
// in the verdict log.
func failedFor(c *censorRun, blocker, why string) error {
	reasons, err := c.blockReasons(blocker)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(reasons, func(r string) bool { return strings.HasPrefix(r, why) }) {
		return fmt.Errorf("%s blocked for %q, not for %q: the control proves nothing of that signal", blocker, reasons, why)
	}
	return nil
}
