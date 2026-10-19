package agent

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
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
		NewConfigurator: func(netcfg.Owner) (netcfg.Configurator, error) {
			return nil, errors.New("no configurator in this test")
		},
		NewTUN: func(string, int) (wgtun.Device, error) {
			return nil, errors.New("no TUN in this test")
		},
		NewGuard: func() routetable.Guard { return nil },
		NewRouteTable: func(*slog.Logger, routetable.Guard) (dataplane.RouteTable, error) {
			return nil, errors.New("no route table in this test")
		},
		ClearConfig:     func(netcfg.Owner) error { return nil },
		ClearRouteTable: func(routetable.Guard) error { return nil },
		SetSystemDNS: func(dns.SystemConfig) (dns.System, error) {
			return nil, errors.New("no resolver configuration in this test")
		},
		SystemUpstreams: func([]netip.Addr) ([]netip.Addr, error) {
			return nil, errors.New("no system upstreams in this test")
		},
		Transports: Transports,
	}
}

func testPlatform() Platform {
	return Platform{
		Host:       testHost(),
		LockHost:   func() (func(), error) { return func() {}, nil },
		RestoreDNS: func() error { return nil },
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
		base.Host.Transports = asks.transports(reg)
		sess := newFakeSession(s.id)
		sess.config <- s.workerConfig(t, s.a, 1)
		done := make(chan error, 1)
		go func() { done <- serveSpace(base.Log, base)(w.ctx, sess.Session) }()
		w.waitLog(t, `msg="map applied"`)
		w.stop()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := asks.got(); !slices.Equal(got, []bool{false}) {
			t.Errorf("markSockets asked %v", got)
		}
	})
}
