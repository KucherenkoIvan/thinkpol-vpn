package localapi

import (
	"bytes"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/packettest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
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

func TestWorkerLastExitReachesStatusAndCLI(t *testing.T) {
	const reason = "start: exec /nonexistent/thinkpol-worker: no such file"
	st := agent.Status{
		Connection: agent.Serving,
		Workers: []agent.WorkerStatus{{
			Space: netmap.SpaceID{0xab}, Ready: false, Starts: 1, LastExit: reason + "\x1b]0;pwned\x07",
		}},
	}
	out := statusProto(st)
	if got := out.GetWorkers()[0].GetLastExit(); got != agent.Sanitize(reason+"\x1b]0;pwned\x07") {
		t.Fatalf("last_exit %q", got)
	}
	var text bytes.Buffer
	if err := WriteStatus(&text, out, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), reason) {
		t.Fatalf("render missing spawn reason:\n%s", text.String())
	}
	if strings.Contains(text.String(), "\x1b") {
		t.Fatalf("raw ESC in render:\n%s", text.String())
	}
}

// Every router, path and route table counter reaches the status under a
// name of its own, the route table's only in route-table mode.
func TestEveryCounterHasAName(t *testing.T) {
	var dp dataplane.Status
	dp.RouteTable.Enforced = true
	n := uint64(0)
	for _, v := range []reflect.Value{reflect.ValueOf(&dp.Router).Elem(), reflect.ValueOf(&dp.Path).Elem(), reflect.ValueOf(&dp.RouteTable).Elem()} {
		for i := range v.NumField() {
			switch f := v.Field(i); f.Kind() {
			case reflect.Uint64:
				n++
				f.SetUint(n)
			case reflect.Int:
				n++
				f.SetInt(int64(n))
			}
		}
	}
	dp.InterfaceReapplies = n + 1
	got := dataPlaneProto(&dp, 0).GetCounters()
	seen := map[uint64]bool{}
	for _, v := range got {
		seen[v] = true
	}
	for v := uint64(1); v <= n+1; v++ {
		if !seen[v] {
			t.Errorf("counter %d of the status has no name", v)
		}
	}
	dp.RouteTable.Enforced = false
	for name := range dataPlaneProto(&dp, 0).GetCounters() {
		if strings.HasPrefix(name, "route_table.") {
			t.Errorf("%s outside route-table mode", name)
		}
	}
}
