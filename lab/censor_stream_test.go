//go:build lab

package lab_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// TestTCPResetReachesBothEnds checks block-ip reset on an established
// connection (data: true lets the handshake through and resets the first
// data segment): the censor's RST reaches device-a, from server-1's
// address, and server-1, from device-a's, over both families; both have
// the hop limit the router sends with, so neither was forwarded from the
// other end; and the data itself never reaches server-1.
func TestTCPResetReachesBothEnds(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	listenTCP(t, server)
	settings, err := json.Marshal(map[string]any{
		"destinations": []string{server.IPv4(lab.NetServers).String(), server.IPv6(lab.NetServers).String()},
		"verdict":      "reset",
		"data":         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := startCensor(t, l, []censor.ModuleConfig{{Name: "block-ip", Settings: settings}})

	filter := fmt.Sprintf("tcp port %d", tcpProbePort)
	devCap, serverCap := dev.Capture(t, filter), server.Capture(t, filter)
	for _, dst := range serverAddrs(server) {
		src := devAddrFor(dev, dst)
		// The handshake completes, then one line of data; nc's exit says
		// nothing the captures don't.
		_, _ = execRead(dev, 30*time.Second, "sh", "-c",
			fmt.Sprintf("{ sleep 1; echo hello; sleep 2; } | nc -w 5 %s %d || true", dst, tcpProbePort))
		devCap.WaitFor(t, 10*time.Second, func(p lab.Packet) bool {
			flags, ok := tcpFlags(p)
			return ok && !p.Outgoing && p.Src == dst && p.SrcPort == tcpProbePort && flags&censor.Rst != 0 && hopLimit(p) == 64
		})
		serverCap.WaitFor(t, 10*time.Second, func(p lab.Packet) bool {
			flags, ok := tcpFlags(p)
			return ok && !p.Outgoing && p.Src == src && p.DstPort == tcpProbePort && flags&censor.Rst != 0 && hopLimit(p) == 64
		})
	}
	if err := serverCap.Complete(); err != nil {
		t.Fatal(err)
	}
	for _, p := range serverCap.Packets() {
		if !p.Outgoing && len(p.Payload) > 0 {
			t.Errorf("server-1 got %d bytes of data from %s: the censor must drop the segment it resets", len(p.Payload), p.Src)
		}
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
	for _, dst := range serverAddrs(server) {
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Dst == dst && e.Verdict == censor.Reset && e.Module == "block-ip"
		}) {
			t.Errorf("no block-ip reset to %s in the verdict log", dst)
		}
	}
}

// TestCensorReplaysClientHello sends a real ClientHello from device-a to
// server-1 in two segments, the server name in the second, through replay:
// the module tags the flow only once the record is whole, and replays it,
// from the router, to server-1, which then holds the ClientHello twice,
// over both families.
func TestCensorReplaysClientHello(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	dev, server, router := l.Node(lab.DeviceA), l.Node(lab.Server1), l.Node(lab.Router)
	const port = 18443
	ch := goClientHello(t)
	if i := bytes.Index(ch, []byte("example.net")); i < 100 {
		t.Fatalf("the server name is at %d: the first segment would carry it", i)
	}
	dev.WriteFile(t, "/tmp/ch", ch)
	got := map[netip.Addr]string{}
	for _, a := range serverAddrs(server) {
		got[a] = fmt.Sprintf("/tmp/got-%s", strings.ReplaceAll(a.String(), ":", "_"))
		server.Start(t, "sh", "-c", fmt.Sprintf("exec nc %s -k -l -s %s -p %d > %s", ncFamily(a), a, port, got[a]))
	}
	waitListeners(t, server, port, 2)
	settings, err := json.Marshal(map[string]any{
		"destinations": []string{server.IPv4(lab.NetServers).String(), server.IPv6(lab.NetServers).String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := startCensor(t, l, []censor.ModuleConfig{{Name: "replay", Settings: settings}})

	routerCap := router.Capture(t, fmt.Sprintf("tcp port %d", port))
	for _, dst := range serverAddrs(server) {
		src := devAddrFor(dev, dst)
		// Two writes with a pause between: the first 100 bytes, then the
		// rest once the first is acknowledged.
		_, _ = execRead(dev, 30*time.Second, "sh", "-c", fmt.Sprintf(
			"{ head -c 100 /tmp/ch; sleep 0.5; tail -c +101 /tmp/ch; sleep 2; } | nc -w 4 %s %d || true", dst, port))
		n, err := pollReceived(server, got[dst], 2*len(ch))
		if err != nil {
			t.Fatal(err)
		}
		if n != 2*len(ch) {
			t.Errorf("server-1 at %s got %d bytes, want the %d-byte ClientHello twice", dst, n, len(ch))
			continue
		}
		b := []byte(server.MustExec(t, "cat", got[dst]))
		if !bytes.Equal(b[:len(ch)], ch) || !bytes.Equal(b[len(ch):], ch) {
			t.Errorf("server-1 at %s got bytes other than the ClientHello twice", dst)
		}
		var segments int
		for _, p := range routerCap.Packets() {
			if !p.Outgoing && p.Src == src && p.Dst == dst && len(p.Payload) > 0 {
				segments++
			}
		}
		if segments < 2 {
			t.Errorf("device-a's ClientHello to %s crossed the router in %d segments, want 2", dst, segments)
		}
		routerAddr := router.IPv4(lab.NetServers)
		if dst.Is6() {
			routerAddr = router.IPv6(lab.NetServers)
		}
		routerCap.WaitFor(t, 5*time.Second, func(p lab.Packet) bool {
			return p.Outgoing && p.Src == routerAddr && p.Dst == dst && p.DstPort == port && bytes.HasPrefix(p.Payload, []byte{0x16, 0x03})
		})
		if !c.logged(t, func(e verdictLine) bool {
			return e.Event == censor.EventTag && e.Module == "replay" && e.Key.Src == src && e.Key.Dst == dst && e.Bytes == uint64(len(ch))
		}) {
			t.Errorf("no replay tag of %s -> %s at %d bytes in the verdict log", src, dst, len(ch))
		}
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
}

// TestCensorSeesUpstream checks the topology of TP-026's upstream tell: in
// lab.Upstream, an entry's connection to the camouflage target crosses the
// router, and the censor there sees it, over both families.
func TestCensorSeesUpstream(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Upstream())
	entry, target := l.Node(lab.Server1), l.Node(lab.Camouflage)
	const port = 18444
	targets := []netip.Addr{target.IPv4(lab.NetWorld), target.IPv6(lab.NetWorld)}
	for _, a := range targets {
		target.Start(t, "nc", ncFamily(a), "-k", "-l", "-s", a.String(), "-p", fmt.Sprint(port))
	}
	waitListeners(t, target, port, 2)
	c := startCensor(t, l, []censor.ModuleConfig{})

	for _, dst := range targets {
		if ok, err := untilAnswer(20*time.Second, func() (bool, error) { return tcpReaches(entry, dst, port, 2) }); err != nil {
			t.Fatal(err)
		} else if !ok {
			t.Errorf("server-1 can't reach the camouflage target at %s", dst)
		}
		src := entry.IPv4(lab.NetServers)
		if dst.Is6() {
			src = entry.IPv6(lab.NetServers)
		}
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Src == src && e.Key.Dst == dst && e.Key.DstPort == port
		}) {
			t.Errorf("the censor didn't see server-1's connection %s -> %s:%d", src, dst, port)
		}
	}
	if err := c.healthy(t); err != nil {
		t.Fatal(err)
	}
}

// goClientHello is the first TLS record a Go client sends: a real
// ClientHello, about 1.5 KB with the post-quantum key share Go offers by
// default, so more than one segment on a 1500-byte MTU.
func goClientHello(t *testing.T) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: "example.net"}).Handshake()
		_ = c.Close()
	}()
	defer func() { _ = s.Close() }()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(s, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// waitListeners waits for n TCP listeners on port in node.
func waitListeners(t *testing.T, node *lab.Node, port, n int) {
	t.Helper()
	lab.Eventually(t, 30*time.Second, func() error {
		out, err := execRead(node, pollTimeout, "ss", "-H", "-lnt", fmt.Sprintf("sport = :%d", port))
		if err != nil {
			return err
		}
		if got := strings.TrimSpace(out); got == "" || len(strings.Split(got, "\n")) < n {
			return fmt.Errorf("listeners on %d: %q", port, out)
		}
		return nil
	})
}

// ncFamily is nc's flag for a's family.
func ncFamily(a netip.Addr) string {
	if a.Is6() {
		return "-6"
	}
	return "-4"
}

// devAddrFor is device-a's address in dst's family.
func devAddrFor(dev *lab.Node, dst netip.Addr) netip.Addr {
	if dst.Is4() {
		return dev.IPv4(lab.NetDevices)
	}
	return dev.IPv6(lab.NetDevices)
}

// hopLimit is a captured packet's TTL or hop limit as it arrived.
func hopLimit(p lab.Packet) int {
	switch {
	case len(p.IP) >= 20 && p.IP[0]>>4 == 4:
		return int(p.IP[8])
	case len(p.IP) >= 40 && p.IP[0]>>4 == 6:
		return int(p.IP[7])
	}
	return -1
}
