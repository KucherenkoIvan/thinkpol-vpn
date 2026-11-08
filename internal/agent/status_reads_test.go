package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
)

// hostCalls records every call a node makes into its host's network
// through the platform (TUNs, the interface's configurator, the route
// table, the OS's resolver configuration and upstreams) and every dial
// of its transports.
type hostCalls struct {
	mu    sync.Mutex
	calls []string
}

func (h *hostCalls) add(format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, fmt.Sprintf(format, args...))
}

func (h *hostCalls) list() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// record makes plat's host ports and reg's dials go through h.
func (h *hostCalls) record(plat *Platform) {
	tun := plat.NewTUN
	plat.NewTUN = func(name string, mtu int) (wgtun.Device, error) { h.add("NewTUN"); return tun(name, mtu) }
	plat.NewConfigurator = func(netcfg.Owner) (netcfg.Configurator, error) {
		h.add("NewConfigurator")
		return recordedConfigurator{h: h, c: &failingConfigurator{}}, nil
	}
	plat.NewRouteTable = func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) {
		h.add("NewRouteTable")
		return recordedRouteTable{h: h}, nil
	}
	plat.ClearConfig = func(netcfg.Owner) error { h.add("ClearConfig"); return nil }
	plat.ClearRouteTable = func(routetable.Guard) error { h.add("ClearRouteTable"); return nil }
	plat.SetSystemDNS = func(dns.SystemConfig) (dns.System, error) {
		h.add("SetSystemDNS")
		return recordedSystem{h: h}, nil
	}
	plat.SystemUpstreams = func([]netip.Addr) ([]netip.Addr, error) {
		h.add("SystemUpstreams")
		return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
	}
	plat.RestoreDNS = func() error { h.add("RestoreDNS"); return nil }
}

type recordedConfigurator struct {
	h *hostCalls
	c netcfg.Configurator
}

func (r recordedConfigurator) Apply(ctx context.Context, c netcfg.Config) error {
	r.h.add("Configurator.Apply")
	return r.c.Apply(ctx, c)
}

func (r recordedConfigurator) DefaultRoute(ctx context.Context, f netcfg.Family) (netcfg.Route, error) {
	r.h.add("Configurator.DefaultRoute")
	return r.c.DefaultRoute(ctx, f)
}

func (r recordedConfigurator) Survey(ctx context.Context) (netcfg.Survey, error) {
	r.h.add("Configurator.Survey")
	return r.c.Survey(ctx)
}

func (r recordedConfigurator) Watch(ctx context.Context) (<-chan struct{}, error) {
	r.h.add("Configurator.Watch")
	return r.c.Watch(ctx)
}

func (r recordedConfigurator) Close() error { r.h.add("Configurator.Close"); return r.c.Close() }

// recordedRouteTable records what changes the host; its Status is the
// enforcer's own record, not a host call.
type recordedRouteTable struct{ h *hostCalls }

func (r recordedRouteTable) Enforce(context.Context, routetable.Want) error {
	r.h.add("RouteTable.Enforce")
	return nil
}
func (recordedRouteTable) Status() routetable.Status { return routetable.Status{Enforced: true} }
func (r recordedRouteTable) Close() error            { r.h.add("RouteTable.Close"); return nil }

// recordedSystem records what changes the OS's resolver configuration;
// its Problem is the configuration's own record, read by the status.
type recordedSystem struct{ h *hostCalls }

func (r recordedSystem) Update(dns.SystemConfig) error { r.h.add("DNS.Update"); return nil }
func (recordedSystem) Problem() error                  { return nil }
func (r recordedSystem) Restore() error                { r.h.add("DNS.Restore"); return nil }

// dialRecorder is a memory network whose dials are recorded.
type dialRecorder struct {
	*memory.Network
	h *hostCalls
}

func (d dialRecorder) Dialer() transport.Dialer { return d }

func (d dialRecorder) Dial(ctx context.Context, endpoint string, cfg transport.DialConfig) (transport.Link, error) {
	d.h.add("Dial %s", endpoint)
	return d.Network.Dial(ctx, endpoint, cfg)
}

// A connected device's Status reads its state and nothing else: it asks
// no host port for anything (TUN, interface, route table, the OS's
// resolver configuration or upstreams) and its transports dial nothing.
// What this can't see: a status that reached the network or the host
// around the node's ports and transports (a bare net.Dial, say).
func TestStatusAsksTheHostAndTheNetworkNothing(t *testing.T) {
	s := newTestSpace(t)
	net, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	var h hostCalls
	deviceReg, err := transport.NewRegistry(dialRecorder{Network: net, h: &h})
	if err != nil {
		t.Fatal(err)
	}
	b := startDevice(t, s, deviceReg, true, deviceOpt{
		prepare: func(c *Config, p *Platform) {
			c.DNS = true
			h.record(p)
		},
		tuning: func(t *tuning) { t.dnsPort = 5353 },
	})
	b.connection(t, Connected)
	eventually(t, func() bool {
		st := b.node.Status()
		return st.Health().Level == HealthOK && st.Interface != ""
	})
	before := h.list()
	for range 100 {
		if st := b.node.Status(); st.Connection != Connected || st.DataPlane == nil {
			t.Fatalf("status %+v", st)
		}
	}
	after := h.list()
	if len(after) != len(before) {
		t.Errorf("Status called the host or the network: %v", after[len(before):])
	}
	if len(before) == 0 {
		t.Fatal("nothing recorded while the device connected: the recorders aren't in place")
	}
}
