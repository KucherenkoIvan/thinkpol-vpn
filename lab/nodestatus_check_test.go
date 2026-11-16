//go:build lab

package lab_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// statusJSON is st as `thinkpol status -json` writes it.
func statusJSON(t *testing.T, st *localapiv1.Status) nodeStatus {
	t.Helper()
	var b bytes.Buffer
	if err := localapi.WriteJSON(&b, st); err != nil {
		t.Fatal(err)
	}
	got, err := parseStatus(b.String())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The lab's status checks read the JSON the CLI writes, and each fails on
// a status that lacks its fact: a check that passed whatever the status
// said would leave the lab test using it without an oracle.
func TestStatusChecksFailWithoutTheirFact(t *testing.T) {
	t.Parallel()
	device := &localapiv1.Status{
		Mode: localapiv1.Mode_MODE_DEVICE, MapVersion: 7, Connection: localapiv1.Connection_CONNECTION_CONNECTED,
		Health: &localapiv1.Health{Level: localapiv1.HealthLevel_HEALTH_LEVEL_DOWN, Problems: []string{"no_link_up", "dns_not_protected"}},
		DataPlane: &localapiv1.DataPlane{
			Mtu: 1380, Ipv6Off: "mtu_below_1280", Interface: "thinkpol0",
			Neighbors: []*localapiv1.Neighbor{{NodeId: "431756c42f1667bf", Up: true}},
			Counters:  map[string]uint64{"route_table.routes": 12, "router.no_route": 1 << 40},
		},
		LastRunCrashed: true,
	}
	server := &localapiv1.Status{
		Mode: localapiv1.Mode_MODE_SERVER, MapVersion: 7, Connection: localapiv1.Connection_CONNECTION_SERVING,
		Uplink: &localapiv1.Uplink{Interface: "eth0", Ipv4: true},
	}
	cases := []struct {
		name  string
		base  *localapiv1.Status
		check statusCheck
		lacks []func(*localapiv1.Status)
	}{
		{"a device's map applied", device, mapApplied("7"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.MapVersion = 6 },
			func(s *localapiv1.Status) { s.Retrying = true },
			func(s *localapiv1.Status) { s.Removed = true },
			func(s *localapiv1.Status) { s.DataPlane.LastApplyError = "router" },
			func(s *localapiv1.Status) { s.DataPlane = nil },
			func(s *localapiv1.Status) { s.Connection = localapiv1.Connection_CONNECTION_CONNECTING },
		}},
		{"a server's map applied", server, mapApplied("7"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.MapVersion = 8 },
			func(s *localapiv1.Status) { s.Retrying = true },
		}},
		{"mode", device, inMode("device"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.Mode = localapiv1.Mode_MODE_SERVER },
		}},
		{"connection", device, connection("connected"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.Connection = localapiv1.Connection_CONNECTION_DISCONNECTED },
		}},
		{"health", device, health("down", "no_link_up"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.Health.Problems = []string{"neighbor_down"} },
			func(s *localapiv1.Status) { s.Health.Level = localapiv1.HealthLevel_HEALTH_LEVEL_DEGRADED },
		}},
		{"a problem", device, problem("dns_not_protected"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.Health.Problems = []string{"no_link_up"} },
		}},
		{"no problem", device, noProblem("dns_upstreams_stale"), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.Health.Problems = append(s.Health.Problems, "dns_upstreams_stale") },
		}},
		{"the uplink", server, uplink("eth0", true, false), []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.Uplink.Ipv6 = true },
			func(s *localapiv1.Status) { s.Uplink.Ipv4 = false },
			func(s *localapiv1.Status) { s.Uplink.Interface = "eth1" },
			func(s *localapiv1.Status) { s.Uplink = nil },
		}},
		{"the route table", device, routeTableEnforced, []func(*localapiv1.Status){
			func(s *localapiv1.Status) { delete(s.DataPlane.Counters, "route_table.routes") },
		}},
		{"IPv6 off", device, ipv6Off, []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.DataPlane.Ipv6, s.DataPlane.Ipv6Off = true, "" },
		}},
		{"a link up", device, linkUp, []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.DataPlane.Neighbors[0].Up = false },
			func(s *localapiv1.Status) { s.DataPlane.Neighbors = nil },
		}},
		{"the data plane", device, dataPlaneUp, []func(*localapiv1.Status){
			func(s *localapiv1.Status) { s.DataPlane = nil },
		}},
	}
	for _, c := range cases {
		if err := statusJSON(t, c.base).check(c.check); err != nil {
			t.Errorf("%s: fails on a status that has it: %v", c.name, err)
		}
		for i, lack := range c.lacks {
			st := proto.CloneOf(c.base)
			lack(st)
			if statusJSON(t, st).check(c.check) == nil {
				t.Errorf("%s: passes on a status without it (%d)", c.name, i)
			}
		}
	}

	// What tests read from the status as values.
	st := statusJSON(t, device)
	if st.DataPlane.MTU != 1380 || !st.LastRunCrashed {
		t.Errorf("mtu %d, last run crashed %v", st.DataPlane.MTU, st.LastRunCrashed)
	}
	if v, ok := st.counter("router.no_route"); !ok || v != 1<<40 {
		t.Errorf("counter router.no_route: %d, %v", v, ok)
	}
	if _, ok := st.counter("router.foreign_source"); ok {
		t.Error("a counter the status doesn't have")
	}
}
