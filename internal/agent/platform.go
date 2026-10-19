package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// Platform is what a node needs of its host, built once by the
// composition root (cmd/thinkpol's platform function) for the OS it runs
// on: the data plane's adapters, and everything that touches the host
// outside one. internal/agent builds none of it and only calls what is
// here; tests put fakes into the same struct.
type Platform struct {
	// NewTUN creates the overlay's TUN and its network configurator (one
	// owner per network namespace: a second node agent fails now, before
	// anything changed).
	NewTUN func(name string) (wgtun.Device, netcfg.Configurator, error)
	// NewGuard is the host's leak guard for the route table (nil where the
	// host has none yet: Windows' is TP-047/TP-048's).
	NewGuard func() routetable.Guard
	// NewRoutes takes route-table enforcement, with guard (nil: none).
	NewRoutes func(log *slog.Logger, guard routetable.Guard) (dataplane.RouteTable, error)
	// ClearOwner removes what a dead configurator of one owner left.
	ClearOwner func(o netcfg.Owner) error
	// RestoreDNS puts back what a crashed run left in the OS's resolver
	// configuration, before anything of the node runs.
	RestoreDNS func() error
	// LockHost takes the agent lock: one node agent per host, held until
	// the node stops or the process ends.
	LockHost func() (func(), error)
	// SetSystemDNS points the OS's resolver at the node's (dns.SetSystem).
	SetSystemDNS func(c dns.SystemConfig) (dns.System, error)
	// SystemUpstreams are the resolvers the OS used before the node
	// pointed it at its own (dns.SystemUpstreams).
	SystemUpstreams func(exclude []netip.Addr) ([]netip.Addr, error)
	// NewSupervisor builds a server's supervisor (supervisor.New).
	NewSupervisor func(o supervisor.Options) (*supervisor.Supervisor, error)
}

// clearNetwork removes what a device's crashed run left in the host's
// routing, for both of its owners, in this order: route-table
// enforcement's routes (its rejects outlive the TUN) with its leak guard,
// then the overlay's (on macOS they go with the utun, but stay in the
// overlay's record), each owner's record with them. The second is cleared
// whatever the first says.
func (p Platform) clearNetwork() error {
	var errs []error
	for _, o := range []netcfg.Owner{netcfg.OwnerRouteTable, netcfg.OwnerOverlay} {
		if err := p.ClearOwner(o); err != nil && !errors.Is(err, errors.ErrUnsupported) {
			errs = append(errs, fmt.Errorf("%v: %w", o, err))
		}
	}
	return errors.Join(errs...)
}
