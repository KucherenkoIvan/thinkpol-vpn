package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Host is what one data plane needs of its network stack: the adapters
// for the OS it runs on, per OS. The agent sequences it and never
// constructs it. The zero value's BlobNet is the node's real network.
type Host struct {
	// NewConfigurator takes the network configuration of one owner (one
	// owner per network namespace: a second node agent fails now, before
	// anything changed).
	NewConfigurator func(o netcfg.Owner) (netcfg.Configurator, error)
	// NewTUN creates the overlay's TUN.
	NewTUN func(name string, mtu int) (wgtun.Device, error)
	// NewGuard is the host's leak guard for the route table (nil where
	// the host has none yet: Windows' is TP-047/TP-048's).
	NewGuard func() routetable.Guard
	// NewRouteTable takes route-table enforcement, with guard (nil: none).
	NewRouteTable func(log *slog.Logger, guard routetable.Guard) (dataplane.RouteTable, error)
	// ClearConfig removes what a dead configurator of one owner left.
	ClearConfig func(o netcfg.Owner) error
	// ClearRouteTable removes what route-table enforcement left, with the
	// leak guard it ran with.
	ClearRouteTable func(guard routetable.Guard) error
	// SetSystemDNS points the OS's resolver at the node's (dns.SetSystem).
	SetSystemDNS func(c dns.SystemConfig) (dns.System, error)
	// SystemUpstreams are the resolvers the OS used before the node
	// pointed it at its own (dns.SystemUpstreams).
	SystemUpstreams func(exclude []netip.Addr) ([]netip.Addr, error)
	// Transports is the node's transport registry: every transport a map
	// may name. markSockets asks for sockets marked past the route table
	// where the host marks them; a sandboxed worker asks for none.
	Transports func(markSockets bool) (*transport.Registry, error)
	// BlobNet is the blob services' network: a loopback overlay in tests
	// and labs, the node's real network when zero.
	BlobNet blobs.Net
}

// Platform is what a node needs of its host: one data plane's Host, and
// what touches the host outside one. internal/agent builds none of it and
// only sequences what is here; tests put fakes into the same struct.
type Platform struct {
	Host
	// LockHost takes the agent lock: one node agent per host, held until
	// the node stops or the process ends.
	LockHost func() (func(), error)
	// RestoreDNS puts back what a crashed run left in the OS's resolver
	// configuration, before anything of the node runs.
	RestoreDNS func() error
}

// clearNetwork removes what a crashed run left in the host's routing, in
// this order: route-table enforcement's routes (its rejects outlive the
// TUN) with its leak guard, then the overlay's (on macOS they go with the
// utun, but stay in the overlay's record), each owner's record with them.
// The second is cleared whatever the first says; what failed is logged.
func (h Host) clearNetwork(log *slog.Logger) {
	var errs []error
	if err := h.ClearRouteTable(h.NewGuard()); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		errs = append(errs, fmt.Errorf("%v: %w", netcfg.OwnerRouteTable, err))
	}
	if err := h.ClearConfig(netcfg.OwnerOverlay); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		errs = append(errs, fmt.Errorf("%v: %w", netcfg.OwnerOverlay, err))
	}
	if err := errors.Join(errs...); err != nil {
		log.Warn("removing a previous run's routes failed", "err", err)
	}
}
