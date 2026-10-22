package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/blobs"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Host is what a device's data plane needs of its network stack, per OS:
// what any data plane needs (WorkerHost), and the adapters only a device
// uses (DeviceHost).
type Host struct {
	WorkerHost
	DeviceHost
}

// WorkerHost is what any data plane needs of its network stack, a
// server's worker's included: its network namespace's.
type WorkerHost struct {
	// NewConfigurator takes the network configuration of one owner (one
	// owner per network namespace: a second node agent fails now, before
	// anything changed).
	NewConfigurator func(o netcfg.Owner) (netcfg.Configurator, error)
	// NewTUN creates the overlay's TUN.
	NewTUN func(name string, mtu int) (wgtun.Device, error)
	// Transports builds the node's transport registry; markSockets marks
	// its sockets past the route table (routetable.SocketControl).
	Transports func(markSockets bool) (*transport.Registry, error)
	// BlobNet is the blob services' network; zero is the node's own
	// sockets.
	BlobNet blobs.Net
}

// DeviceHost is what only a device's data plane uses of the host: the
// route table and its leak guard, clearing what a crashed run left, and
// the OS's resolvers and their configuration. A server's worker never
// gets one. Every field is set.
type DeviceHost struct {
	// NewGuard returns the host's leak guard for the route table, or nil
	// where the host has none yet (Windows: TP-047/TP-048).
	NewGuard func() routetable.Guard
	// NewRouteTable takes route-table enforcement, with guard (nil: none).
	NewRouteTable func(log *slog.Logger, guard routetable.Guard) (RouteEnforcer, error)
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
}

// RouteEnforcer is route-table enforcement on the host
// (routetable.Enforcer), which the agent adapts to the engine's
// dataplane.RouteTable.
type RouteEnforcer interface {
	Enforce(ctx context.Context, w routetable.Want) error
	Status() routetable.Status
	Close() error
}

// Platform is what a node needs of its host: one data plane's Host, and
// what touches the host outside one (the agent lock, a crashed run's
// resolver configuration, the last connect request). The agent only
// sequences what is here. Every field is set.
type Platform struct {
	Host
	// LockHost takes the agent lock: one node agent per host, held until
	// the node stops or the process ends.
	LockHost func() (func(), error)
	// RestoreDNS puts back what a crashed run left in the OS's resolver
	// configuration, before anything of the node runs.
	RestoreDNS func() error
	// ConnectRecord keeps a device's last connect request of this boot
	// (HostConnectRecord).
	ConnectRecord ConnectRecord
}

// ErrAnotherAgent: another node agent holds the host's agent lock.
var ErrAnotherAgent = errors.New("another thinkpol agent is running on this host")

// ClearHost undoes what a crashed run left on the host, as a start that
// doesn't connect does: the routing (clearNetwork) and the OS's resolver
// configuration. Both are tried; what failed is returned. The caller
// holds the host's agent lock, so no running agent's state is taken.
func (p Platform) ClearHost() error {
	return errors.Join(p.clearRouting(), p.RestoreDNS())
}

// clearNetwork removes what a crashed run left in the host's routing
// (clearRouting); what failed is logged.
func (h DeviceHost) clearNetwork(log *slog.Logger) {
	if err := h.clearRouting(); err != nil {
		log.Warn("removing a previous run's routes failed", "err", err)
	}
}

// clearRouting removes what a crashed run left in the host's routing, in
// this order: route-table enforcement's routes (its rejects outlive the
// TUN) with its leak guard, then the overlay's (on macOS they go with the
// utun, but stay in the overlay's record), each owner's record with them.
// The second is cleared whatever the first says.
func (h DeviceHost) clearRouting() error {
	var errs []error
	if err := h.ClearRouteTable(h.NewGuard()); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		errs = append(errs, fmt.Errorf("%v: %w", netcfg.OwnerRouteTable, err))
	}
	if err := h.ClearConfig(netcfg.OwnerOverlay); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		errs = append(errs, fmt.Errorf("%v: %w", netcfg.OwnerOverlay, err))
	}
	return errors.Join(errs...)
}
