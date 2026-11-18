package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/tun"
)

// platform builds what a node needs of its host, per OS: one data plane's
// Host, and what touches the host outside one. Wiring only: every field
// is a reference to an existing function, but for the kill switch's
// timing in a lab node (labKillSwitchReapply).
func platform() agent.Platform {
	reapply := labKillSwitchReapply(os.Getenv)
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
				// The direct destinations' timeout is three periods, as
				// firewall.DirectTimeout is the agent's default's.
				NewKillSwitch:     newKillSwitch(3 * reapply),
				KillSwitchReapply: reapply,
			},
		},
		LockHost:      agent.HostLock,
		RestoreDNS:    dns.RestoreSystem,
		ConnectRecord: agent.HostConnectRecord(),
		Inspect: agent.Inspector{
			Interface:  netcfg.InspectInterface,
			Routes:     netcfg.Inspect,
			Guard:      inspectGuard,
			KillSwitch: inspectKillSwitch,
			DNS:        dns.Inspect,
			DropIns:    service.HostDropIns,
		},
	}
}

// newRouteTable takes route-table enforcement, with its leak guard
// (nil: none), in the route table's own argument order.
func newRouteTable(log *slog.Logger, guard routetable.Guard) (agent.RouteEnforcer, error) {
	return routetable.New(guard, log)
}

// labKillSwitchReapply is the kill switch's re-apply period in a lab node
// (THINKPOL_LAB=1): THINKPOL_LAB_KILL_SWITCH_REAPPLY, a duration from 1 s
// to under a third of firewall.DirectTimeout (shorter than the agent's
// default, the direct destinations' timeout with it), which the lab's
// kill-switch test sets to run the re-apply tick and their expiry in
// seconds. Zero, the defaults, anywhere else and for any other value.
func labKillSwitchReapply(getenv func(string) string) time.Duration {
	if getenv("THINKPOL_LAB") != "1" {
		return 0
	}
	d, err := time.ParseDuration(getenv("THINKPOL_LAB_KILL_SWITCH_REAPPLY"))
	if err != nil || d < time.Second || 3*d >= firewall.DirectTimeout {
		return 0
	}
	return d
}
