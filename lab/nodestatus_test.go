//go:build lab

package lab_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// upCommand is the command line of `thinkpol up` with args on node n, after
// env (NAME=value) if any. A server-* runs in server mode unless args name
// a mode: a node runs in server mode only when told to, whatever its kind
// in the map (TP-111). Every lab test starts its nodes' `thinkpol up`
// through here, so a change to how a node starts is made once.
func upCommand(n *lab.Node, env []string, args ...string) []string {
	var cmd []string
	if len(env) > 0 {
		cmd = append([]string{"env"}, env...)
	}
	cmd = append(cmd, "thinkpol", "up")
	if strings.HasPrefix(n.Name, "server-") && !slices.ContainsFunc(args, func(a string) bool { return a == "-mode" || strings.HasPrefix(a, "-mode=") }) {
		cmd = append(cmd, "-mode", "server")
	}
	return append(cmd, args...)
}

// startUp starts `thinkpol up` with args on node n (upCommand), stopped when
// the test ends.
func startUp(t *testing.T, n *lab.Node, args ...string) *lab.Process {
	t.Helper()
	return n.Start(t, upCommand(n, nil, args...)...)
}

// startUpWithoutMode starts `thinkpol up` with args and no -mode on node n,
// stopped when the test ends: TP-111's case, a server-* started without
// -mode runs as a device.
func startUpWithoutMode(t *testing.T, n *lab.Node, args ...string) *lab.Process {
	t.Helper()
	return n.Start(t, append([]string{"thinkpol", "up"}, args...)...)
}

// nodeStatus is the part of `thinkpol status -json` the lab reads
// (the localapi package doc, "JSON"; the Status message in
// proto/thinkpol/localapi/v1/localapi.proto). 64-bit integers are strings.
type nodeStatus struct {
	Mode       string `json:"mode"`
	SpaceID    string `json:"space_id"`
	MapVersion string `json:"map_version"`
	Removed    bool   `json:"removed"`
	Connection string `json:"connection"`
	Retrying   bool   `json:"retrying"`
	Health     struct {
		Level    string   `json:"level"`
		Problems []string `json:"problems"`
	} `json:"health"`
	DataPlane *struct {
		MTU            int               `json:"mtu"`
		IPv6           bool              `json:"ipv6"`
		IPv6Off        string            `json:"ipv6_off"`
		LastApplyError string            `json:"last_apply_error"`
		Neighbors      []neighborStatus  `json:"neighbors"`
		Counters       map[string]string `json:"counters"`
		Interface      string            `json:"interface"`
	} `json:"data_plane"`
	Workers []struct {
		SpaceID string `json:"space_id"`
		Ready   bool   `json:"ready"`
	} `json:"workers"`
	RulePreset     string `json:"rule_preset"`
	LastRunCrashed bool   `json:"last_run_crashed"`
	RulesEnforced  bool   `json:"rules_enforced"`
	Uplink         *struct {
		Interface string `json:"interface"`
		IPv4      bool   `json:"ipv4"`
		IPv6      bool   `json:"ipv6"`
		Error     string `json:"error"`
	} `json:"uplink"`
	SchemaVersion int `json:"schema_version"`

	raw string
}

type neighborStatus struct {
	NodeID string `json:"node_id"`
	Up     bool   `json:"up"`
	// UpSince is zero while down (`null`).
	UpSince time.Time `json:"up_since"`
}

// errSchemaVersion: the status is of a schema the lab doesn't read; no
// retry changes that.
var errSchemaVersion = errors.New("schema version")

// parseStatus reads `thinkpol status -json`'s output.
func parseStatus(out string) (nodeStatus, error) {
	var st nodeStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return nodeStatus{}, fmt.Errorf("status -json: %w\n%s", err, out)
	}
	if st.SchemaVersion != localapi.SchemaVersion {
		return nodeStatus{}, fmt.Errorf("status -json: %w %d, the lab reads %d", errSchemaVersion, st.SchemaVersion, localapi.SchemaVersion)
	}
	st.raw = out
	return st, nil
}

// readStatus is node n's `thinkpol status -json`, with extra flags (such as
// -socket) if any.
func readStatus(n *lab.Node, timeout time.Duration, flags ...string) (nodeStatus, error) {
	out, err := execRead(n, timeout, append([]string{"thinkpol", "status", "-json"}, flags...)...)
	if err != nil {
		return nodeStatus{}, err
	}
	return parseStatus(out)
}

// statusCheck is a fact a status shows: nil when it does, else what it
// shows instead.
type statusCheck func(nodeStatus) error

// waitStatus waits up to a minute for node n's status to pass every check,
// and returns that status.
func waitStatus(t *testing.T, n *lab.Node, checks ...statusCheck) nodeStatus {
	t.Helper()
	return waitStatusFor(t, n, 60*time.Second, nil, checks...)
}

// waitStatusFor waits up to timeout for node n's status, read with flags,
// to pass every check, and returns that status.
func waitStatusFor(t *testing.T, n *lab.Node, timeout time.Duration, flags []string, checks ...statusCheck) nodeStatus {
	t.Helper()
	st, err := statusWithin(n, timeout, flags, checks...)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// statusWithin waits up to timeout for node n's status, read with flags, to
// pass every check: for callers that return the failure rather than fail
// the test.
func statusWithin(n *lab.Node, timeout time.Duration, flags []string, checks ...statusCheck) (nodeStatus, error) {
	deadline := time.Now().Add(timeout)
	var last nodeStatus // the last status read, kept through later read errors
	for {
		st, err := readStatus(n, pollTimeout, flags...)
		switch {
		case errors.Is(err, errSchemaVersion):
			return nodeStatus{}, fmt.Errorf("%s: %w", n.Name, err)
		case err == nil:
			last = st
			if err = st.check(checks...); err == nil {
				return st, nil
			}
		}
		if time.Now().After(deadline) {
			if last.raw != "" && st.raw == "" {
				return last, fmt.Errorf("%s: not within %s: %w; the last status read:\n%s", n.Name, timeout, err, last.raw)
			}
			return last, fmt.Errorf("%s: not within %s: %w", n.Name, timeout, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// check is nil when st passes every check, else the first failure with the
// status it read.
func (st nodeStatus) check(checks ...statusCheck) error {
	for _, c := range checks {
		if err := c(st); err != nil {
			return fmt.Errorf("%w; status:\n%s", err, st.raw)
		}
	}
	return nil
}

func (st nodeStatus) hasProblem(code string) bool { return slices.Contains(st.Health.Problems, code) }

// counter is a data-plane counter by name, and whether the status has it.
func (st nodeStatus) counter(name string) (uint64, bool) {
	if st.DataPlane == nil {
		return 0, false
	}
	s, ok := st.DataPlane.Counters[name]
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// inMode: the node runs in mode ("device" or "server").
func inMode(mode string) statusCheck {
	return func(st nodeStatus) error {
		if st.Mode != mode {
			return fmt.Errorf("mode %q, want %q", st.Mode, mode)
		}
		return nil
	}
}

// connection: the node's connection is c ("connected", "disconnected",
// "connecting", "serving").
func connection(c string) statusCheck {
	return func(st nodeStatus) error {
		if st.Connection != c {
			return fmt.Errorf("connection %q, want %q", st.Connection, c)
		}
		return nil
	}
}

// mapApplied: the node runs map version, applied: a server serves it, a
// device's data plane is up on it, and nothing is being retried. A
// server's connection reads serving only once its first serve of the map
// has ended, each of its listeners serving, and a later map's version
// once that map is served alike; it passes only with at least one worker,
// each ready: sandboxed, and routed to by the listeners. The workers apply
// the map after; their log says when.
func mapApplied(version string) statusCheck {
	return func(st nodeStatus) error {
		switch {
		case st.MapVersion != version:
			return fmt.Errorf("map version %s, want %s", st.MapVersion, version)
		case st.Retrying:
			return fmt.Errorf("retrying map version %s", version)
		case st.Removed:
			return fmt.Errorf("removed from its space in map version %s", version)
		case st.Mode == "server":
			if len(st.Workers) == 0 {
				return fmt.Errorf("map version %s, no workers yet", version)
			}
			for _, w := range st.Workers {
				if !w.Ready {
					return fmt.Errorf("map version %s, worker of space %s not ready", version, w.SpaceID)
				}
			}
			return connection("serving")(st)
		case st.DataPlane == nil:
			return fmt.Errorf("map version %s, no data plane", version)
		case st.DataPlane.LastApplyError != "":
			return fmt.Errorf("map version %s: applying it failed at %q", version, st.DataPlane.LastApplyError)
		}
		return connection("connected")(st)
	}
}

// health: the node's health level is level, with each of problems among
// its problems.
func health(level string, problems ...string) statusCheck {
	return func(st nodeStatus) error {
		if st.Health.Level != level {
			return fmt.Errorf("health %s %v, want %s", st.Health.Level, st.Health.Problems, level)
		}
		for _, p := range problems {
			if !st.hasProblem(p) {
				return fmt.Errorf("health %s %v, want %s among them", st.Health.Level, st.Health.Problems, p)
			}
		}
		return nil
	}
}

// problem: code is among the node's health problems.
func problem(code string) statusCheck {
	return func(st nodeStatus) error {
		if !st.hasProblem(code) {
			return fmt.Errorf("no %s among the problems %v", code, st.Health.Problems)
		}
		return nil
	}
}

// noProblem: code is not among the node's health problems.
func noProblem(code string) statusCheck {
	return func(st nodeStatus) error {
		if st.hasProblem(code) {
			return fmt.Errorf("%s among the problems %v", code, st.Health.Problems)
		}
		return nil
	}
}

// uplink: a server's uplink is iface, carrying IPv4 and IPv6 as v4 and v6
// say.
func uplink(iface string, v4, v6 bool) statusCheck {
	return func(st nodeStatus) error {
		if u := st.Uplink; u == nil || u.Interface != iface || u.IPv4 != v4 || u.IPv6 != v6 {
			return fmt.Errorf("uplink %+v, want %s with ipv4 %v, ipv6 %v", u, iface, v4, v6)
		}
		return nil
	}
}

// routeTableEnforced: a device's route table enforces its rules. Its
// counters are in the status when it enforces them and also when it
// failed (route_table_not_enforced), so both are read.
func routeTableEnforced(st nodeStatus) error {
	if _, ok := st.counter("route_table.routes"); !ok {
		return fmt.Errorf("the route table enforces nothing")
	}
	return noProblem("route_table_not_enforced")(st)
}

// dataPlaneUp: a device's data plane is up.
func dataPlaneUp(st nodeStatus) error {
	if st.DataPlane == nil {
		return fmt.Errorf("no data plane")
	}
	return nil
}

// linkUp: a device has a neighbor whose link is up.
func linkUp(st nodeStatus) error {
	if st.DataPlane != nil && slices.ContainsFunc(st.DataPlane.Neighbors, func(n neighborStatus) bool { return n.Up }) {
		return nil
	}
	return fmt.Errorf("no neighbor up")
}

// ipv6Off: a device's overlay carries no IPv6.
func ipv6Off(st nodeStatus) error {
	if st.DataPlane == nil || st.DataPlane.IPv6 || st.DataPlane.IPv6Off == "" {
		return fmt.Errorf("the overlay's IPv6 is not off")
	}
	return nil
}
