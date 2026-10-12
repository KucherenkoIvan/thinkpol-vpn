//go:build lab

package lab_test

import (
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestShapingCapture is what a censor at the router sees of udp's padding
// (TP-027): device-a sends the same WireGuard-like packets unshaped to port
// 4500 and padded to buckets to port 4501 (udp's TestLabSendShaped), and
// the capture compares the datagram sizes.
func TestShapingCapture(t *testing.T) {
	t.Parallel()
	const unshapedPort, shapedPort = 4500, 4501
	// udp's wireguardLikeSizes (87) times labRepeats (3), on each port.
	const perPort = 261
	// labBuckets in udp's tests.
	buckets := []int{128, 256, 512, 1024, 1452}

	l := lab.Start(t, lab.Standard())
	device, server, router := l.Node(lab.DeviceA), l.Node(lab.Server1), l.Node(lab.Router)
	server.WriteFile(t, "/tmp/sink.nft", []byte(`table inet shaping_sink {
	chain in {
		type filter hook input priority 0; policy accept;
		udp dport { 4500, 4501 } drop
	}
}
`))
	server.MustExec(t, "nft", "-f", "/tmp/sink.nft")

	target := server.IPv4(lab.NetServers)
	// Only the copy leaving the router: capture's ring holds about 500
	// frames, and the sender's pacing gives it about half a second of a
	// busy machine holding tcpdump up before it would drop any.
	capture := router.Capture(t, fmt.Sprintf("outbound and udp and dst host %s and (dst port %d or dst port %d)", target, unshapedPort, shapedPort))
	device.RunGoTests(t, "./internal/dataplane/transport/udp", "-test.run", "^TestLabSendShaped$", "-lab-target="+target.String())

	sizes := map[uint16]map[int]int{unshapedPort: {}, shapedPort: {}} // port → datagram size → count
	lab.Eventually(t, 10*time.Second, func() error {
		sizes[unshapedPort], sizes[shapedPort] = map[int]int{}, map[int]int{}
		for _, p := range capture.Packets() {
			if p.Network == lab.NetServers && p.Outgoing && p.Src == device.IPv4(lab.NetDevices) {
				sizes[p.DstPort][len(p.Payload)]++
			}
		}
		if total(sizes[unshapedPort]) != perPort || total(sizes[shapedPort]) != perPort {
			return fmt.Errorf("captured %d unshaped and %d shaped datagrams, want %d each", total(sizes[unshapedPort]), total(sizes[shapedPort]), perPort)
		}
		return nil
	})

	unshaped, shaped := slices.Sorted(maps.Keys(sizes[unshapedPort])), slices.Sorted(maps.Keys(sizes[shapedPort]))
	t.Logf("unshaped: %d datagrams in %d sizes: %v", total(sizes[unshapedPort]), len(unshaped), sizes[unshapedPort])
	t.Logf("shaped:   %d datagrams in %d sizes: %v", total(sizes[shapedPort]), len(shaped), sizes[shapedPort])

	// Unshaped, each packet size shows as itself plus udp's overhead: the
	// WireGuard handshake (148 + 18 path header + overhead) among them.
	if len(unshaped) < 80 {
		t.Errorf("unshaped traffic showed only %d sizes", len(unshaped))
	}
	if sizes[unshapedPort][18+148+udp.Overhead] == 0 {
		t.Errorf("no handshake-sized datagram in the unshaped capture")
	}
	// Padded, only the buckets show.
	for _, n := range shaped {
		if !slices.Contains(buckets, n) {
			t.Errorf("a %d-byte datagram is not a bucket of %v", n, buckets)
		}
	}
	if len(shaped) > len(buckets) {
		t.Errorf("padded traffic showed %d sizes", len(shaped))
	}
}

func total(m map[int]int) int {
	n := 0
	for _, c := range m {
		n += c
	}
	return n
}
