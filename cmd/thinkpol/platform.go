package main

import (
	"log/slog"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
)

// platform builds what a node needs of its host, per OS: one data plane's
// Host, and what touches the host outside one. Wiring only: every field
// is a reference to an existing function.
func platform() agent.Platform {
	return agent.Platform{
		Host: agent.Host{
			WorkerHost: agent.WorkerHost{
				NewConfigurator: netcfg.New,
				NewTUN:          tun.Create,
				Transports:      agent.Transports,
			},
			DeviceHost: agent.DeviceHost{
				NewGuard:        newGuard,
				NewRouteTable:   newRouteTable,
				ClearConfig:     netcfg.Clear,
				ClearRouteTable: routetable.Clear,
				SetSystemDNS:    dns.SetSystem,
				SystemUpstreams: dns.SystemUpstreams,
			},
		},
		LockHost:      agent.HostLock,
		RestoreDNS:    dns.RestoreSystem,
		ConnectRecord: agent.HostConnectRecord(),
	}
}

// newRouteTable takes route-table enforcement, with its leak guard
// (nil: none), in the route table's own argument order.
func newRouteTable(log *slog.Logger, guard routetable.Guard) (agent.RouteEnforcer, error) {
	return routetable.New(guard, log)
}
