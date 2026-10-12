//go:build linux && !android

package router_test

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
)

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// On Linux's TUN with offloads, which coalesces a batch in place and
// reports its write in bytes, Delivered still counts the packets.
func TestDeliveredCountsPacketsOnALinuxTUN(t *testing.T) {
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	ns := "routertest-" + hex.EncodeToString(b)
	ip(t, "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	dev, err := tun.CreateInNamespace("/run/netns/"+ns, tun.DefaultName, 1400)
	if err != nil {
		t.Fatal(err)
	}
	if dev.BatchSize() == 1 {
		_ = dev.Close()
		t.Fatal("the TUN came up without offloads")
	}
	ip(t, "-n", ns, "addr", "add", "100.64.0.1/24", "dev", tun.DefaultName)
	ip(t, "-n", ns, "link", "set", "dev", tun.DefaultName, "up")

	const n, offset = 16, 16
	// One flow of equal datagrams, which the TUN may coalesce (UDP GRO).
	batch := func() [][]byte {
		bufs := make([][]byte, n)
		for i := range bufs {
			p := packettest.UDPDatagram(netip.MustParseAddrPort("100.64.0.2:4000"), netip.MustParseAddrPort("100.64.0.1:5000"), make([]byte, 1000))
			bufs[i] = append(make([]byte, offset), p...)
		}
		return bufs
	}
	raw, err := dev.Write(batch(), offset)
	if err != nil {
		_ = dev.Close()
		t.Fatal(err)
	}
	t.Logf("the TUN reports a batch of %d packets as %d", n, raw)

	r := router.New(dev)
	t.Cleanup(func() { _ = r.Close() })
	e, err := r.NewEgress("overlay", 1400)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetTable(router.Table{Local: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}); err != nil {
		t.Fatal(err)
	}
	if got, err := e.Write(batch(), offset); err != nil || got != n {
		t.Fatalf("Write: %d, %v; want %d packets", got, err, n)
	}
	if s, c := e.Status(), r.Counters(); s.Delivered != n || c.Delivered != n {
		t.Fatalf("delivered %d (egress) and %d (router), want %d packets", s.Delivered, c.Delivered, n)
	}
}
