//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/KucherenkoIvan/go-kernel/grpckit"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// statusNode is a connected device whose status the test sets. It
// serves only the status: anything else fails the test, so `status` is
// seen to read the service's state and nothing more.
type statusNode struct {
	t  *testing.T
	st agent.Status
}

func (n *statusNode) Status() agent.Status { return n.st }
func (n *statusNode) Connect(context.Context) error {
	n.t.Error("status called Connect")
	return nil
}
func (n *statusNode) Disconnect(context.Context) error {
	n.t.Error("status called Disconnect")
	return nil
}
func (n *statusNode) SetRulePreset(context.Context, string) error {
	n.t.Error("status called SetRulePreset")
	return nil
}
func (n *statusNode) SetConnectOnBoot(bool) error {
	n.t.Error("status called SetConnectOnBoot")
	return nil
}
func (n *statusNode) SetKillSwitch(context.Context, bool) error {
	n.t.Error("status called SetKillSwitch")
	return nil
}
func (n *statusNode) SetAllowLAN(context.Context, bool) error {
	n.t.Error("status called SetAllowLAN")
	return nil
}
func (n *statusNode) Diagnose(context.Context, bool) agent.Diagnostics {
	n.t.Error("status called Diagnose, which reads the host")
	return agent.Diagnostics{}
}

// serveStatus serves the local API for node on a socket of its own and
// returns the socket's path.
func serveStatus(t *testing.T, node localapi.Node) string {
	t.Helper()
	return serveAPI(t, node, localapi.Policy{ServiceUID: uint32(os.Geteuid())})
}

// serveAPI is serveStatus deciding who may call by p; the socket is this
// process's either way, so a caller reaches the service, and p alone
// refuses it.
func serveAPI(t *testing.T, node localapi.Node, p localapi.Policy) string {
	t.Helper()
	// Not t.TempDir: its long path would pass the unix socket path's
	// limit (104 bytes on macOS).
	dir, err := os.MkdirTemp("", "tpst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "api", "api.sock")
	l, err := localapi.Listen(socket, localapi.Policy{ServiceUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := localapi.NewGRPCServer(ctx, localapi.Options{Node: node, Logs: logring.New(1 << 10), Log: slog.New(slog.DiscardHandler)}, p)
	done := make(chan error, 1)
	go func() { done <- grpckit.Serve(ctx, srv, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the local API didn't stop")
		}
	})
	return socket
}

// connectedDevice is a connected device with a link, and its zero values
// (no handshake yet, nothing skipped, no rule preset problem).
func connectedDevice(t *testing.T) *statusNode {
	return &statusNode{t: t, st: agent.Status{
		Mode: agent.ModeDevice, Space: netmap.SpaceID{0xab, 1}, MapVersion: 7, Connection: agent.Connected,
		RulePreset: "space", RulesEnforced: true, Interface: "tun0",
		DataPlane: &dataplane.Status{MTU: 1328, IPv6: true,
			Peers:     []dataplane.PeerStatus{{ID: netmap.NodeID{0, 0, 0, 0, 0, 0, 0, 1}, Device: "overlay"}},
			Neighbors: []path.NeighborStatus{{Node: path.NodeID{0, 0, 0, 0, 0, 0, 0, 1}, Links: []path.LinkStatus{{Transport: "udp", Dialed: true}}}},
		},
	}}
}

// runStatusCLI runs `thinkpol status args...` against socket.
func runStatusCLI(t *testing.T, socket string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &errOut}
	if code := run(context.Background(), e, append([]string{"status", "-socket", socket}, args...)); code != 0 {
		t.Fatalf("status %v: exit %d\n%s", args, code, errOut.String())
	}
	return out.String()
}

var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// checkFields fails unless obj holds every field of md by its proto
// (snake_case) name and nothing else, and so on down every message in it.
// A map's keys are data, not field names.
func checkFields(t *testing.T, md protoreflect.MessageDescriptor, obj map[string]any, at string) {
	t.Helper()
	fields := md.Fields()
	for key := range obj {
		if !snakeCase.MatchString(key) || fields.ByName(protoreflect.Name(key)) == nil {
			t.Errorf("%s: field %q is not the schema's snake_case name", at, key)
		}
	}
	for i := range fields.Len() {
		fd := fields.Get(i)
		name := string(fd.Name())
		v, ok := obj[name]
		if !ok {
			t.Errorf("%s: no field %q", at, name)
			continue
		}
		if fd.Message() == nil || fd.IsMap() || fd.Message().FullName().Parent() == "google.protobuf" {
			continue
		}
		var elems []any
		if fd.IsList() {
			elems, _ = v.([]any)
		} else if v != nil {
			elems = []any{v}
		}
		for j, el := range elems {
			sub, ok := el.(map[string]any)
			if !ok {
				t.Errorf("%s.%s: %v is not an object", at, name, el)
				continue
			}
			checkFields(t, fd.Message(), sub, fmt.Sprintf("%s.%s[%d]", at, name, j))
		}
	}
}

func TestStatusJSONHasEveryFieldBySchemaName(t *testing.T) {
	socket := serveStatus(t, connectedDevice(t))
	out := runStatusCLI(t, socket, "-json")
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	// The CLI's schema version, the one key that isn't Status's.
	if obj["schema_version"] != float64(localapi.SchemaVersion) {
		t.Errorf("schema_version %v, want %d", obj["schema_version"], localapi.SchemaVersion)
	}
	delete(obj, "schema_version")
	checkFields(t, (&localapiv1.Status{}).ProtoReflect().Descriptor(), obj, "status")
	// Zero values are there as themselves: false, "", an empty list, null.
	dp, _ := obj["data_plane"].(map[string]any)
	for key, want := range map[string]any{"removed": false, "retrying": false, "rule_preset_unavailable": false, "maps_refused": "0", "uplink": nil} {
		if got := obj[key]; got != want {
			t.Errorf("%s: %#v, want %#v", key, got, want)
		}
	}
	if dp["ipv6_off"] != "" || dp["interface"] != "tun0" || fmt.Sprint(dp["skipped"]) != "[]" || fmt.Sprint(obj["workers"]) != "[]" {
		t.Errorf("data plane %v, workers %v", dp, obj["workers"])
	}
	if peer := dp["peers"].([]any)[0].(map[string]any); peer["last_handshake"] != nil || peer["first_hop"] != "" {
		t.Errorf("a peer with no handshake: %v", peer)
	}
}

// errEnough stops a watch once the test has seen enough.
var errEnough = errors.New("enough")

// linesWriter keeps what is written and fails the write after the
// given number.
type linesWriter struct {
	bytes.Buffer
	writes, after int
}

func (w *linesWriter) Write(p []byte) (int, error) {
	n, _ := w.Buffer.Write(p)
	if w.writes++; w.writes >= w.after {
		return n, errEnough
	}
	return n, nil
}

// `status -watch -json` is NDJSON: one whole object per line, so a line
// reader (a `while read` loop, the lab's harness) gets one status a line.
func TestStatusWatchJSONIsOneObjectPerLine(t *testing.T) {
	socket := serveStatus(t, connectedDevice(t))
	out := &linesWriter{after: 3}
	e := env{stdin: strings.NewReader(""), stdout: out, stderr: io.Discard}
	if err := runStatus(context.Background(), e, []string{"-socket", socket, "-watch", "-interval", "10ms", "-json"}); !errors.Is(err, errEnough) {
		t.Fatalf("status -watch -json: %v\n%s", err, out.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3:\n%s", len(lines), out.String())
	}
	for _, l := range lines {
		var st map[string]any
		if err := json.Unmarshal([]byte(l), &st); err != nil || st["connection"] != "connected" || st["schema_version"] != float64(localapi.SchemaVersion) {
			t.Errorf("line %q: %v", l, err)
		}
	}
}
