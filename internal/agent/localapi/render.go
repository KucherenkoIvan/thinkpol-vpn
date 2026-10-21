package localapi

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// The renderers write what a Client returned, already sanitized, for a
// person (or, WriteJSON, for a script).

// WriteStatus writes st as of now.
func WriteStatus(w io.Writer, st *localapiv1.Status, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	line := func(format string, args ...any) { _, _ = fmt.Fprintf(tw, format+"\n", args...) }

	line("state:\t%s", displayName(st.GetConnection()))
	health := displayName(st.GetHealth().GetLevel())
	if p := st.GetHealth().GetProblems(); len(p) > 0 {
		health += ": " + strings.Join(p, ", ")
	}
	line("health:\t%s", health)
	space := st.GetSpaceId()
	if st.GetRemoved() {
		space += " (removed from it)"
	}
	line("space:\t%s, map version %d", space, st.GetMapVersion())
	if n := st.GetMapsRefused(); n > 0 {
		line("maps refused:\t%d since the node started (the service's log says why)", n)
	}
	line("mode:\t%s", displayName(st.GetMode()))
	if p := st.GetRulePreset(); p != "" {
		switch {
		case st.GetRulePresetUnavailable():
			p += " (unavailable in this space: failing closed)"
		case !st.GetRulesEnforced():
			p += " (applies once connected)"
		}
		line("rule preset:\t%s", p)
	}
	if st.GetRetrying() {
		line("retrying:\tyes, see the service's log")
	}
	if dp := st.GetDataPlane(); dp != nil {
		writeDataPlane(line, dp, now)
	}
	if ws := st.GetWorkers(); len(ws) > 0 {
		line("workers:")
		for _, wk := range ws {
			s := "not ready"
			if wk.GetReady() {
				s = "ready " + ago(wk.GetReadySince(), now)
			} else if wk.GetRestartAt() != nil {
				s = "restarting in " + round(wk.GetRestartAt().AsTime().Sub(now)).String()
			}
			if !wk.GetReady() && wk.GetLastExit() != "" {
				s += " (" + wk.GetLastExit() + ")"
			}
			line("  %s\t%s\t%d starts", wk.GetSpaceId(), s, wk.GetStarts())
		}
	}
	if e := st.GetUplink(); e != nil {
		if e.GetInterface() == "" {
			line("uplink:\tnone (%s): no space has egress", e.GetError())
		} else {
			line("uplink:\t%s, ipv4 %s, ipv6 %s, forwarding %s/%s", e.GetInterface(),
				onOff(e.GetIpv4()), onOff(e.GetIpv6()), onOff(e.GetForwarding4()), onOff(e.GetForwarding6()))
		}
	}
	if ls := st.GetPublicListeners(); len(ls) > 0 {
		line("public listeners:")
		for _, l := range ls {
			line("  %s\trouted %d\tunauthenticated %d\tno space %d\toverloaded %d\trejected links %d",
				l.GetTransport(), l.GetRouted(), l.GetUnauthenticated(), l.GetNoSpace(), l.GetStreamsOverloaded(), l.GetRejected())
		}
	}
	return tw.Flush()
}

func writeDataPlane(line func(string, ...any), dp *localapiv1.DataPlane, now time.Time) {
	ipv6 := "on"
	if !dp.GetIpv6() {
		ipv6 = "off"
		if dp.GetIpv6Off() != "" {
			ipv6 += " (" + dp.GetIpv6Off() + ")"
		}
	}
	line("overlay:\tmtu %d, ipv6 %s, %d listeners", dp.GetMtu(), ipv6, dp.GetListeners())
	if e := dp.GetLastApplyError(); e != "" {
		line("last apply:\tfailed at %s", e)
	}
	if es := dp.GetEgresses(); len(es) > 0 {
		names := make([]string, 0, len(es))
		for _, e := range es {
			names = append(names, fmt.Sprintf("%s (mtu %d)", e.GetName(), e.GetMtu()))
		}
		line("egresses:\t%s", strings.Join(names, ", "))
	}
	writePeers(line, dp.GetPeers(), now)
	writeNeighbors(line, dp.GetNeighbors())
	if ss := dp.GetSkipped(); len(ss) > 0 {
		line("skipped from the map:")
		for _, s := range ss {
			line("  %s %s:\t%s", s.GetItem(), s.GetNodeId(), s.GetReason())
		}
	}
	writeCounters(line, dp.GetCounters())
}

func writePeers(line func(string, ...any), ps []*localapiv1.Peer, now time.Time) {
	if len(ps) == 0 {
		return
	}
	line("peers:")
	for _, p := range ps {
		via := "no path yet"
		if hop := p.GetFirstHop(); hop == p.GetNodeId() {
			via = "direct"
		} else if hop != "" {
			via = "via " + hop
		}
		hs := "no handshake"
		if p.GetLastHandshake() != nil {
			hs = "handshake " + ago(p.GetLastHandshake(), now)
		}
		line("  %s\t%s\t%s\t%s\trx %s\ttx %s", p.GetNodeId(), strings.Join(p.GetAddresses(), " "), via, hs,
			byteCount(p.GetRxBytes()), byteCount(p.GetTxBytes()))
	}
}

func writeNeighbors(line func(string, ...any), ns []*localapiv1.Neighbor) {
	if len(ns) == 0 {
		return
	}
	line("neighbors:")
	for _, n := range ns {
		state := "down"
		if n.GetUp() {
			state = "up " + round(n.GetUpFor().AsDuration()).String()
		}
		var links []string
		for _, l := range n.GetLinks() {
			var flags []string
			if l.GetDialed() {
				flags = append(flags, "dialed")
			}
			if l.GetActive() {
				flags = append(flags, "active")
			}
			if l.GetUp() {
				flags = append(flags, "up")
			}
			links = append(links, l.GetTransport()+" ("+strings.Join(flags, " ")+")")
		}
		line("  %s\t%s\trtt %s\t%s", n.GetNodeId(), state, rtt(n.GetRtt()), strings.Join(links, ", "))
	}
}

// writeCounters writes the route table's counters, and the nonzero drops.
func writeCounters(line func(string, ...any), counters map[string]uint64) {
	if n := counters["route_table.routes"]; n > 0 {
		line("route table:\t%d routes, re-applied %d times", n, counters["route_table.reapplies"])
		if ahead := counters["route_table.rules_ahead"]; ahead > 0 {
			line("\t%d policy rules of other software come first and may route around the tunnel", ahead)
		}
		if ahead := counters["route_table.overlay_routes_ahead"]; ahead > 0 {
			line("\t%d routes of other software take overlay addresses around the tunnel", ahead)
		}
	}
	var drops []string
	for _, name := range slices.Sorted(maps.Keys(counters)) {
		if v := counters[name]; v > 0 && counterKinds[name] == dropCounter {
			drops = append(drops, fmt.Sprintf("%s %d", name, v))
		}
	}
	if len(drops) > 0 {
		line("dropped:\t%s", strings.Join(drops, ", "))
	}
}

// counterKinds are dataPlaneCounters' kinds by name; a counter the table
// doesn't know (a newer service's) is a drop.
var counterKinds = func() map[string]counterKind {
	m := make(map[string]counterKind, len(dataPlaneCounters))
	for _, c := range dataPlaneCounters {
		m[c.name] = c.kind
	}
	return m
}()

// WriteSpaces writes the spaces, the active one marked.
func WriteSpaces(w io.Writer, spaces []*localapiv1.Space) error {
	for _, s := range spaces {
		mark := ""
		if s.GetActive() {
			mark = "  (active)"
		}
		if _, err := fmt.Fprintf(w, "%s%s\n", s.GetId(), mark); err != nil {
			return err
		}
	}
	return nil
}

// WriteLogLines writes log lines, after a note of how many were missed.
func WriteLogLines(w io.Writer, lines []string, missed uint64) error {
	if missed > 0 {
		if _, err := fmt.Fprintf(w, "... %d lines dropped from the log before they could be sent\n", missed); err != nil {
			return err
		}
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON writes m as JSON, for scripts.
func WriteJSON(w io.Writer, m proto.Message) error {
	b, err := protojson.MarshalOptions{Multiline: true, EmitUnpopulated: false}.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// displayNames are what WriteStatus calls the status's enum values.
var displayNames = map[protoreflect.Enum]string{
	localapiv1.Connection_CONNECTION_UNSPECIFIED:    "unspecified",
	localapiv1.Connection_CONNECTION_DISCONNECTED:   "disconnected",
	localapiv1.Connection_CONNECTION_CONNECTING:     "connecting",
	localapiv1.Connection_CONNECTION_CONNECTED:      "connected",
	localapiv1.Connection_CONNECTION_SERVING:        "serving",
	localapiv1.HealthLevel_HEALTH_LEVEL_UNSPECIFIED: "unspecified",
	localapiv1.HealthLevel_HEALTH_LEVEL_OK:          "ok",
	localapiv1.HealthLevel_HEALTH_LEVEL_DEGRADED:    "degraded",
	localapiv1.HealthLevel_HEALTH_LEVEL_DOWN:        "down",
	localapiv1.Mode_MODE_UNSPECIFIED:                "unspecified",
	localapiv1.Mode_MODE_DEVICE:                     "device",
	localapiv1.Mode_MODE_SERVER:                     "server",
}

// displayName is e's display name; a value the table doesn't know (a
// newer service's) is "unknown".
func displayName(e protoreflect.Enum) string {
	if name, ok := displayNames[e]; ok {
		return name
	}
	return "unknown"
}

func ago(t *timestamppb.Timestamp, now time.Time) string {
	if t == nil {
		return "never"
	}
	return round(now.Sub(t.AsTime())).String() + " ago"
}

func rtt(d *durationpb.Duration) string {
	if d == nil {
		return "-"
	}
	return d.AsDuration().Round(100 * time.Microsecond).String()
}

func round(d time.Duration) time.Duration { return max(d, 0).Round(time.Second) }

func byteCount(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
