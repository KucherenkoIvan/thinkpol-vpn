package agent

import (
	"errors"
	"log/slog"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// testHost is what tests build where the composition root builds the real
// one: fakes that touch nothing on the host, and loud ones where a test
// should have set its own (the TUN, the route table, the OS resolver
// configuration). No test takes the host's agent lock (hostlock_unix_test.go
// locks files of its own).
func testHost() Host {
	return Host{
		NewConfigurator: func(netcfg.Owner) (netcfg.Configurator, error) {
			return nil, errors.New("no configurator in this test")
		},
		NewTUN: func(string, int) (wgtun.Device, error) {
			return nil, errors.New("no TUN in this test")
		},
		NewGuard: func() routetable.Guard { return nil },
		NewRouteTable: func(*slog.Logger, routetable.Guard) (dataplane.RouteTable, error) {
			return nil, errors.New("no route table in this test")
		},
		ClearConfig:     func(netcfg.Owner) error { return nil },
		ClearRouteTable: func(routetable.Guard) error { return nil },
		SetSystemDNS: func(dns.SystemConfig) (dns.System, error) {
			return nil, errors.New("no resolver configuration in this test")
		},
		SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
			return nil, errors.New("no system upstreams in this test")
		},
		Transports: func(bool) (*transport.Registry, error) {
			return nil, errors.New("no registry in this test")
		},
	}
}

func testPlatform() Platform {
	return Platform{
		Host:       testHost(),
		LockHost:   func() (func(), error) { return func() {}, nil },
		RestoreDNS: func() error { return nil },
	}
}