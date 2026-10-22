package agent

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// inspected records what the test's inspector was asked to read.
type inspected struct {
	mu     sync.Mutex
	asked  []string
	report InterfaceReport
	// hostReads counts the reads of the routes and the guard.
	hostReads int
	routes    netcfg.Inspection
	guard     routetable.GuardReport
}

func (i *inspected) inspector() Inspector {
	return Inspector{
		Interface: func(name string) InterfaceReport {
			i.mu.Lock()
			defer i.mu.Unlock()
			i.asked = append(i.asked, name)
			r := i.report
			if r.Unreadable == "" {
				r.Name = name
			}
			return r
		},
		Routes: func() netcfg.Inspection {
			i.mu.Lock()
			defer i.mu.Unlock()
			i.hostReads++
			return i.routes
		},
		Guard: func(context.Context) routetable.GuardReport {
			i.mu.Lock()
			defer i.mu.Unlock()
			i.hostReads++
			return i.guard
		},
	}
}

func (i *inspected) reads() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hostReads
}

// TestTheHostPartsAreRoots: without host, the routes and the guard aren't
// read at all, and say they are root's; with it, they are what the host's
// readers said, whatever the data plane's state.
func TestTheHostPartsAreRoots(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	insp := &inspected{
		routes: netcfg.Inspection{Routes: []netcfg.HostRoute{{Owner: netcfg.OwnerRouteTable, Family: netcfg.IPv6, Dst: netip.MustParsePrefix("::/0"), Type: "unreachable"}}},
		guard:  routetable.GuardReport{Where: "test", Present: true, Exempt: []netip.Prefix{netip.MustParsePrefix("2001:db8:d0::/48")}},
	}
	b := startDevice(t, s, reg, false, withInspector(insp))
	b.connection(t, Disconnected)
	ctx := context.Background()

	d := b.node.Diagnose(ctx, false)
	if insp.reads() != 0 || d.Routes.RoutesUnreadable != UnreadableRootOnly || d.Routes.RulesUnreadable != UnreadableRootOnly ||
		d.Routes.Routes != nil || d.Guard.Unreadable != UnreadableRootOnly || d.Guard.Present {
		t.Fatalf("not root: %d reads, %+v, %+v", insp.reads(), d.Routes, d.Guard)
	}
	// Disconnected, what is left on the host still shows: a crash's.
	d = b.node.Diagnose(ctx, true)
	if insp.reads() != 2 || len(d.Routes.Routes) != 1 || d.Routes.RoutesUnreadable != "" || !d.Guard.Present || len(d.Guard.Exempt) != 1 {
		t.Fatalf("root: %d reads, %+v, %+v", insp.reads(), d.Routes, d.Guard)
	}
}

func (i *inspected) names() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]string(nil), i.asked...)
}

func withInspector(i *inspected) deviceOpt {
	return deviceOpt{prepare: func(_ *Config, p *Platform) { p.Inspect = i.inspector() }}
}

func TestDiagnoseReadsTheTUNTheDataPlaneRuns(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	insp := &inspected{report: InterfaceReport{Index: 7, MTU: 1328, Up: true, Running: true, Addrs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/10")}}}
	b := startDevice(t, s, reg, false, withInspector(insp))
	ctx := context.Background()

	// Disconnected: no TUN to read, and the snapshot says so rather than
	// showing an empty one.
	b.connection(t, Disconnected)
	d := b.node.Diagnose(ctx, true)
	if d.TUN.Unreadable != UnreadableNoTUN || d.TUN.Name != "" || len(insp.names()) != 0 {
		t.Fatalf("disconnected: TUN %+v, inspector asked for %q", d.TUN, insp.names())
	}
	if d.Status.Connection != Disconnected || d.Status.Space != s.id {
		t.Fatalf("disconnected: status %+v", d.Status)
	}

	if err := b.node.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	b.connection(t, Connected)
	d = b.node.Diagnose(ctx, true)
	if d.Status.Connection != Connected || d.Status.DataPlane == nil {
		t.Fatalf("connected: status %+v", d.Status)
	}
	asked := insp.names()
	if len(asked) != 1 || asked[0] == "" {
		t.Fatalf("connected: the inspector was asked for %q", asked)
	}
	if d.TUN.Unreadable != "" || d.TUN.Name != asked[0] || d.TUN.MTU != 1328 || d.TUN.Index != 7 || !d.TUN.Up || len(d.TUN.Addrs) != 1 {
		t.Fatalf("connected: TUN %+v", d.TUN)
	}

	// What the host couldn't show comes through as the reader said it.
	insp.report = InterfaceReport{Unreadable: "route ip+net: no such network interface"}
	if d = b.node.Diagnose(ctx, true); d.TUN.Unreadable != insp.report.Unreadable || d.TUN.Name != "" {
		t.Fatalf("an unreadable TUN: %+v", d.TUN)
	}
}

// TestDiagnosticsHoldNoSecret takes a connected device's snapshot and
// looks in every string and byte field of it for the device's private
// keys and its links' credentials, in hex, base64 and raw.
func TestDiagnosticsHoldNoSecret(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	startNode(t, reg, s.a, s.verified(t, 1))
	insp := &inspected{report: InterfaceReport{MTU: 1328, Up: true}}
	b := startDevice(t, s, reg, true, withInspector(insp))
	b.connection(t, Connected)
	d := b.node.Diagnose(context.Background(), true)
	if d.Status.DataPlane == nil || d.TUN.Name == "" {
		t.Fatalf("the snapshot holds no data plane to look in: %+v", d)
	}

	var secrets []string
	for _, b := range [][]byte{s.b.Map[:], s.b.WireGuard[:], s.secret} {
		secrets = append(secrets, hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b),
			base64.RawStdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b))
	}
	secrets = append(secrets, string(s.secret))
	leaves := snapshotLeaves(reflect.ValueOf(d))
	if len(leaves) < 10 {
		t.Fatalf("only %d values in the snapshot: %q", len(leaves), leaves)
	}
	for _, l := range leaves {
		for _, sec := range secrets {
			if strings.Contains(l, sec) {
				t.Errorf("the snapshot holds a secret: %q", l)
			}
		}
	}
}

// snapshotLeaves are v's values as text: strings and Stringers as they
// are, bytes (arrays and slices) in hex and base64, numbers as numbers.
func snapshotLeaves(v reflect.Value) []string {
	if !v.IsValid() {
		return nil
	}
	if s, ok := v.Interface().(fmt.Stringer); ok && v.Kind() != reflect.Pointer && v.Kind() != reflect.Struct {
		return []string{s.String()}
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return snapshotLeaves(v.Elem())
	case reflect.String:
		return []string{v.String()}
	case reflect.Array, reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(b), v)
			return []string{hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), string(b)}
		}
		var out []string
		for i := range v.Len() {
			out = append(out, snapshotLeaves(v.Index(i))...)
		}
		return out
	case reflect.Map:
		var out []string
		for _, k := range v.MapKeys() {
			out = append(out, snapshotLeaves(k)...)
			out = append(out, snapshotLeaves(v.MapIndex(k))...)
		}
		return out
	case reflect.Struct:
		if s, ok := v.Interface().(fmt.Stringer); ok {
			return []string{s.String()}
		}
		var out []string
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				out = append(out, snapshotLeaves(v.Field(i))...)
			}
		}
		return out
	}
	return []string{fmt.Sprint(v.Interface())}
}
