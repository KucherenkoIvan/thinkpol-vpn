package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// testHost is the host's adapters as tests see them: fakes that touch
// nothing on the host, and loud ones where a test should have set its own
// (the TUN, the route table, the OS resolver configuration). No test
// takes the host's agent lock (hostlock_unix_test.go locks files of its
// own).
func testHost() Host {
	return Host{
		WorkerHost: WorkerHost{
			NewConfigurator: func(netcfg.Owner) (netcfg.Configurator, error) {
				return nil, errors.New("no configurator in this test")
			},
			NewTUN: func(string, int) (wgtun.Device, error) {
				return nil, errors.New("no TUN in this test")
			},
			Transports: Transports,
		},
		DeviceHost: DeviceHost{
			NewGuard: func() routetable.Guard { return nil },
			NewRouteTable: func(*slog.Logger, routetable.Guard) (RouteEnforcer, error) {
				return noRouteTable{}, nil
			},
			ClearConfig:     func(netcfg.Owner) error { return nil },
			ClearRouteTable: func(routetable.Guard) error { return nil },
			SetSystemDNS: func(dns.SystemConfig) (dns.System, error) {
				return nil, errors.New("no resolver configuration in this test")
			},
			SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
				return nil, errors.New("no system upstreams in this test")
			},
		},
	}
}

func testPlatform() Platform {
	return Platform{
		Host:          testHost(),
		LockHost:      func() (func(), error) { return func() {}, nil },
		RestoreDNS:    func() error { return nil },
		ConnectRecord: &memConnectRecord{},
	}
}

// markAsks records the markSockets of each Transports call.
type markAsks struct {
	mu    sync.Mutex
	marks []bool
}

// transports is a Host's Transports giving reg, recording what it was
// asked for.
func (a *markAsks) transports(reg *transport.Registry) func(bool) (*transport.Registry, error) {
	return func(markSockets bool) (*transport.Registry, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.marks = append(a.marks, markSockets)
		return reg, nil
	}
}

func (a *markAsks) got() []bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.marks)
}

// A device's sockets and the supervisor's (the root namespace's) are
// marked past the route table; a worker's, in its namespace, are not.
func TestTransportsMarkSocketsPerMode(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	for _, tc := range []struct {
		name string
		keys NodeKeys
		mode Mode
	}{{"device", s.b, ModeDevice}, {"supervisor", s.a, ModeServer}} {
		t.Run(tc.name, func(t *testing.T) {
			var asks markAsks
			plat := testPlatform()
			plat.Transports = asks.transports(reg)
			n, err := Prepare(testConfig(s.stateDir(t, tc.keys, 1)), Logs{}, plat)
			if err != nil {
				t.Fatal(err)
			}
			if n.Mode() != tc.mode {
				t.Fatalf("mode %s", n.Mode())
			}
			if _, err := n.Adapters(nil); errors.Is(err, ErrUnsupported) {
				t.Skip(err)
			} else if err != nil {
				t.Fatal(err)
			}
			if got := asks.got(); !slices.Equal(got, []bool{true}) {
				t.Errorf("markSockets asked %v", got)
			}
		})
	}
	t.Run("worker", func(t *testing.T) {
		w := newRunningNode()
		defer w.stop()
		var asks markAsks
		base := w.dataPlane(reg, NodeKeys{}, nil)
		base.Namespace.Transports = asks.transports(reg)
		sess := newFakeSession(s.id)
		sess.config <- s.workerConfig(t, s.a, 1)
		done := make(chan error, 1)
		go func() { done <- serveSpace(base.Log, base)(w.ctx, sess.Session) }()
		w.applied(t, 1)
		w.stop()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := asks.got(); !slices.Equal(got, []bool{false}) {
			t.Errorf("markSockets asked %v", got)
		}
	})
}

// Clearing one owner failing doesn't keep the other's leftovers; an OS
// without an adapter for an owner has nothing to clear.
func TestClearingTheNetworkTriesBothOwners(t *testing.T) {
	var owners []netcfg.Owner
	clearOwner := func(o netcfg.Owner) error {
		owners = append(owners, o)
		if o == netcfg.OwnerRouteTable {
			return errors.New("no routing socket today")
		}
		return nil
	}
	h := DeviceHost{
		NewGuard:        func() routetable.Guard { return nil },
		ClearRouteTable: func(routetable.Guard) error { return clearOwner(netcfg.OwnerRouteTable) },
		ClearConfig:     clearOwner,
	}
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, nil))
	h.clearNetwork(log)
	if !slices.Equal(owners, []netcfg.Owner{netcfg.OwnerRouteTable, netcfg.OwnerOverlay}) {
		t.Errorf("cleared %v", owners)
	}
	if got := out.String(); strings.Count(got, "removing a previous run's routes failed") != 1 ||
		!strings.Contains(got, "route-table: no routing socket today") {
		t.Errorf("log %q", got)
	}
	out.Reset()
	h.ClearRouteTable = func(routetable.Guard) error { return fmt.Errorf("netcfg: %w", errors.ErrUnsupported) }
	h.ClearConfig = func(netcfg.Owner) error { return fmt.Errorf("netcfg: %w", errors.ErrUnsupported) }
	h.clearNetwork(log)
	if out.Len() != 0 {
		t.Errorf("unsupported: %q", out.String())
	}
}

// noRouteTable is the test platform's route table: it takes every Want
// and changes nothing, so a device's data plane runs in route-table mode,
// as in production, and the host's routing stays as it is.
type noRouteTable struct{}

func (noRouteTable) Enforce(context.Context, routetable.Want) error { return nil }
func (noRouteTable) Status() routetable.Status                      { return routetable.Status{Enforced: true} }
func (noRouteTable) Close() error                                   { return nil }

// memConnectRecord is a ConnectRecord in memory, of one boot.
type memConnectRecord struct {
	mu      sync.Mutex
	connect bool
	ok      bool
}

func (r *memConnectRecord) Load() (bool, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connect, r.ok, nil
}

func (r *memConnectRecord) Save(connect bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connect, r.ok = connect, true
	return nil
}
