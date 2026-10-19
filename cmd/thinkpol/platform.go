package main

import (
	"log/slog"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
)

// platform builds what a node needs of its host: the data plane's
// adapters, and everything that touches the host outside one. This is the
// composition root's wiring: internal/agent only receives it, and tests
// fake it.
func platform() agent.Platform {
	return agent.Platform{
		NewTUN:          newTUN,
		NewGuard:        newGuard,
		NewRoutes:       newRouteTable,
		ClearOwner:      clearHostOwner,
		RestoreDNS:      dns.RestoreSystem,
		LockHost:        agent.HostLock,
		SetSystemDNS:    dns.SetSystem,
		SystemUpstreams: dns.SystemUpstreams,
		NewSupervisor:   newSupervisor,
	}
}

// newTUN takes the overlay's network configuration (one owner per network
// namespace: a second node agent fails now, before anything changed) and
// creates the TUN; the engine sets its MTU.
func newTUN(name string) (wgtun.Device, netcfg.Configurator, error) {
	ifc, err := netcfg.New(netcfg.OwnerOverlay)
	if err != nil {
		return nil, nil, err
	}
	dev, err := tun.Create(name, 1420)
	if err != nil {
		_ = ifc.Close()
		return nil, nil, err
	}
	return dev, ifc, nil
}

// newRouteTable takes the host's route-table enforcement (one per network
// namespace, like the overlay's configuration), with guard (nil: none).
func newRouteTable(log *slog.Logger, guard routetable.Guard) (dataplane.RouteTable, error) {
	return routetable.New(guard, log)
}

// clearHostOwner removes what a dead configurator of one owner left: the
// route table's, whose leak guard goes too, closed while the route table's
// owner lock is held and left alone when it can't be taken
// (routetable.Clear).
func clearHostOwner(o netcfg.Owner) error {
	if o == netcfg.OwnerRouteTable {
		return routetable.Clear(newGuard())
	}
	return netcfg.Clear(o)
}

// newSupervisor builds the supervisor, with the root namespace's own
// configurator from here.
func newSupervisor(o supervisor.Options) (*supervisor.Supervisor, error) {
	o.NewRoot = func() (netcfg.Configurator, error) { return netcfg.New(netcfg.OwnerSupervisor) }
	return supervisor.New(o)
}
