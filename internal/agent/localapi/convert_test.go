package localapi

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
)

// bytesTUN reports writes as Linux's TUN does: in bytes, not packets.
type bytesTUN struct{ tun.Device }

func (b bytesTUN) Write(bufs [][]byte, offset int) (int, error) {
	if _, err := b.Device.Write(bufs, offset); err != nil {
		return 0, err
	}
	n := 0
	for _, p := range bufs {
		n += len(p) - offset
	}
	return n, nil
}

// The local API and `thinkpol status` carry the router's delivered and
// forwarded counts as packets, on a TUN that reports its writes in bytes,
// and as traffic, not drops.
func TestDeliveredPacketsReachTheStatus(t *testing.T) {
	ch := tuntest.NewChannelTUN()
	r := router.New(bytesTUN{ch.TUN()})
	t.Cleanup(func() { _ = r.Close() })
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-ch.Inbound:
			case <-stop:
				return
			}
		}
	}()
	e, err := r.NewEgress("overlay", 1400)
	if err != nil {
		t.Fatal(err)
	}
	own := netip.MustParseAddrPort("100.64.0.1:5000")
	if err := r.SetTable(router.Table{Local: []netip.Addr{own.Addr()}, Forward: []*router.Egress{e}}); err != nil {
		t.Fatal(err)
	}
	// 6 packets for the node, 4 it forwards to the internet.
	var bufs [][]byte
	for i := range 10 {
		dst := own
		if i >= 6 {
			dst = netip.MustParseAddrPort("192.0.2.1:443")
		}
		p := packettest.UDPDatagram(netip.MustParseAddrPort("100.64.0.2:4000"), dst, make([]byte, 1000))
		bufs = append(bufs, append(make([]byte, 16), p...))
	}
	if n, err := e.Write(bufs, 16); err != nil || n != 10 {
		t.Fatalf("Write: %d, %v", n, err)
	}

	st := agent.Status{Mode: agent.ModeDevice, Connection: agent.Connected,
		DataPlane: &dataplane.Status{Router: r.Counters(), Egresses: r.Egresses()}}
	out := statusProto(st)
	dp := out.GetDataPlane()
	if got := dp.GetCounters()["router.delivered"]; got != 10 {
		t.Errorf("router.delivered %d, want 10 packets", got)
	}
	if got := dp.GetCounters()["router.forwarded"]; got != 4 {
		t.Errorf("router.forwarded %d, want 4 packets", got)
	}
	if es := dp.GetEgresses(); len(es) != 1 || es[0].GetDelivered() != 10 {
		t.Errorf("egresses %v, want overlay with 10 delivered", es)
	}
	var text bytes.Buffer
	if err := WriteStatus(&text, out, time.Now()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "dropped") {
		t.Errorf("delivered traffic shown as dropped:\n%s", text.String())
	}
}
