package agent

import (
	"errors"
	"log/slog"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// testPlatform is what tests build where the composition root
// (cmd/thinkpol) builds the real one: fakes that touch nothing on the
// host, and loud ones where a test should have set its own (the TUN, the
// route table, the OS resolver configuration). No test takes the host's
// agent lock (hostlock_unix_test.go locks files of its own).
func testPlatform() Platform {
	return Platform{
		NewTUN: func(string) (wgtun.Device, netcfg.Configurator, error) {
			return nil, nil, errors.New("no TUN in this test")
		},
		NewGuard: func() routetable.Guard { return nil },
		NewRoutes: func(*slog.Logger, routetable.Guard) (dataplane.RouteTable, error) {
			return nil, errors.New("no route table in this test")
		},
		ClearOwner: func(netcfg.Owner) error { return nil },
		RestoreDNS: func() error { return nil },
		LockHost:   func() (func(), error) { return func() {}, nil },
		SetSystemDNS: func(dns.SystemConfig) (dns.System, error) {
			return nil, errors.New("no resolver configuration in this test")
		},
		SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
			return nil, errors.New("no system upstreams in this test")
		},
		NewSupervisor: func(supervisor.Options) (*supervisor.Supervisor, error) {
			return nil, supervisor.ErrUnsupported
		},
	}
}
