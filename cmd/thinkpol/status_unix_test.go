//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
func (n *statusNode) Diagnose(context.Context, bool) agent.Diagnostics {
	n.t.Error("status called Diagnose, which reads the host")
	return agent.Diagnostics{}
}

// serveStatus serves the local API for node on a socket of its own and
// returns the socket's path.
func serveStatus(t *testing.T, node localapi.Node) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tpst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "api", "api.sock")
	p := localapi.Policy{ServiceUID: uint32(os.Geteuid())}
	l, err := localapi.Listen(socket, p)
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

// runStatusCLI runs `thinkpol status args...` against socket, every
// connection through dial.
func runStatusCLI(t *testing.T, socket string, dial localapi.Dialer, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &errOut, dial: dial}
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
	out := runStatusCLI(t, socket, nil, "-json")
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	checkFields(t, (&localapiv1.Status{}).ProtoReflect().Descriptor(), obj, "status")
	if obj["schema_version"] != float64(localapi.SchemaVersion) || localapi.SchemaVersion < 1 {
		t.Errorf("schema_version %v, want %d", obj["schema_version"], localapi.SchemaVersion)
	}
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
	// One object, byte-stable: protojson's randomized spacing is gone.
	if again := runStatusCLI(t, socket, nil, "-json"); again != out || strings.Contains(out, ":  ") || !strings.HasSuffix(out, "}\n") {
		t.Errorf("not byte-stable:\n%s\nthen\n%s", out, again)
	}
}

// A newer client's schema version is the one its JSON says, whatever the
// service sent: the JSON holds the client's fields.
func TestStatusJSONSaysTheClientsSchema(t *testing.T) {
	var out bytes.Buffer
	if err := localapi.WriteStatusJSON(&out, &localapiv1.Status{SchemaVersion: 99}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.SchemaVersion != localapi.SchemaVersion {
		t.Fatalf("schema_version %d (%v), want %d:\n%s", got.SchemaVersion, err, localapi.SchemaVersion, out.String())
	}
}

// dialRecorder is a test transport: it lets through the one connection
// status may make, to the local API's socket, fails any other dial, and
// records them all.
type dialRecorder struct {
	socket string
	mu     sync.Mutex
	dials  []string
}

func (d *dialRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, network+" "+address)
	d.mu.Unlock()
	if network != "unix" || address != d.socket {
		return nil, fmt.Errorf("the test transport fails any dial: %s %s", network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestStatusReachesOnlyTheLocalAPI(t *testing.T) {
	socket := serveStatus(t, connectedDevice(t))
	d := &dialRecorder{socket: socket}
	for _, args := range [][]string{nil, {"-json"}} {
		if out := runStatusCLI(t, socket, d.dial, args...); !strings.Contains(strings.ToLower(out), "connected") {
			t.Fatalf("status %v:\n%s", args, out)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.dials) == 0 {
		t.Fatal("status dialed nothing through the test transport")
	}
	for _, got := range d.dials {
		if got != "unix "+socket {
			t.Errorf("status dialed %s", got)
		}
	}
}
