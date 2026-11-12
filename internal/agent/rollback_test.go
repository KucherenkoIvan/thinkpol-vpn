package agent

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// errNoServerHere is the supervisor's configurator in these tests: on
// Linux ClearLeftovers asks for it and fails before it touches the host;
// elsewhere it has nothing to clear.
var errNoServerHere = errors.New("no supervisor's configurator in this test")

// deadAgentHost is a host a dead agent left: its route table's and
// overlay's routes, its resolver configuration, its kill switch and a
// connect choice recorded up. Each clear notes whether it ran under the
// host lock.
type deadAgentHost struct {
	mu       sync.Mutex
	locked   bool // another agent holds the lock
	held     bool
	cleared  []string // what was cleared, each "<what> held=<bool>"
	failDNS  error
	failKill error
	ks       memKillSwitches
	rec      memConnectRecord
}

func newDeadAgentHost() *deadAgentHost {
	h := &deadAgentHost{}
	h.ks.put(&firewall.KillSwitchRules{})
	_ = h.rec.Save(true)
	return h
}

func (h *deadAgentHost) note(what string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cleared = append(h.cleared, fmt.Sprintf("%s held=%v", what, h.held))
}

func (h *deadAgentHost) platform() Platform {
	p := testPlatform()
	p.NewConfigurator = func(o netcfg.Owner) (netcfg.Configurator, error) {
		h.note("configurator " + o.String())
		return nil, errNoServerHere
	}
	p.ClearRouteTable = func(routetable.Guard) error { h.note("route table"); return nil }
	p.ClearConfig = func(o netcfg.Owner) error { h.note("config " + o.String()); return nil }
	p.RestoreDNS = func() error { h.note("DNS"); return h.failDNS }
	p.NewKillSwitch = func() KillSwitch { return failingClose{h: h, KillSwitch: h.ks.new()} }
	p.ConnectRecord = &h.rec
	p.LockHost = func() (func(), error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.locked {
			return nil, fmt.Errorf("%w (it holds the test's lock)", ErrAnotherAgent)
		}
		h.held = true
		return func() { h.mu.Lock(); h.held = false; h.mu.Unlock() }, nil
	}
	return p
}

// failingClose is the host's kill switch, whose Close fails with the
// host's failKill, leaving it in place.
type failingClose struct {
	KillSwitch
	h *deadAgentHost
}

func (k failingClose) Close() error {
	k.h.note("kill switch")
	if k.h.failKill != nil {
		return k.h.failKill
	}
	return k.KillSwitch.Close()
}

// While an agent holds the host lock, rollback is refused and touches
// nothing: the running agent's routes, resolvers, kill switch and connect
// choice stay as they are.
func TestRollbackIsRefusedWhileAnAgentRuns(t *testing.T) {
	h := newDeadAgentHost()
	h.locked = true
	r, err := Rollback(h.platform())
	if !errors.Is(err, ErrAnotherAgent) || !strings.Contains(err.Error(), "thinkpol disconnect") {
		t.Fatalf("Rollback: %v, want ErrAnotherAgent saying how to take the tunnel down", err)
	}
	if len(r.Parts) > 0 || len(h.cleared) > 0 {
		t.Errorf("refused, it still cleared %q (report %+v)", h.cleared, r)
	}
	if h.ks.rules() == nil {
		t.Error("refused, it removed the running agent's kill switch")
	}
	var out bytes.Buffer
	if err := r.Write(&out); err != nil || out.Len() > 0 {
		t.Errorf("refused, the report says %q (%v), want nothing", out.String(), err)
	}
	if connect, ok, _ := h.rec.Load(); !connect || !ok {
		t.Errorf("refused, the connect choice is %v (recorded %v), want up as the running agent left it", connect, ok)
	}
}

// Rollback clears each part a dead agent left, under the host lock, and
// records the boot's connect choice down, so the service's next start
// doesn't put the crash posture's kill switch back; it says so.
func TestRollbackClearsWhatADeadAgentLeftAndRecordsDown(t *testing.T) {
	h := newDeadAgentHost()
	r, err := Rollback(h.platform())
	// On Linux the supervisor's part asks for its configurator, which this
	// test refuses; elsewhere a server has nothing to clear.
	server := r.Parts[0]
	if server.Err != nil && !errors.Is(server.Err, errNoServerHere) {
		t.Errorf("the server's part: %v", server.Err)
	}
	if server.Err == nil && err != nil {
		t.Errorf("Rollback: %v", err)
	}
	for _, p := range r.Parts[1:] {
		if p.Err != nil {
			t.Errorf("%s: %v", p.What, p.Err)
		}
	}
	for _, want := range []string{"route table held=true", "config overlay held=true", "DNS held=true", "kill switch held=true"} {
		if !strings.Contains(strings.Join(h.cleared, "\n"), want) {
			t.Errorf("not cleared under the lock: %s; cleared: %q", want, h.cleared)
		}
	}
	if h.ks.rules() != nil {
		t.Error("the kill switch is still in place")
	}
	if connect, ok, _ := h.rec.Load(); connect || !ok {
		t.Errorf("the connect choice is %v (recorded %v), want recorded down", connect, ok)
	}
	if h.held {
		t.Error("the host lock is still held")
	}
	var out bytes.Buffer
	if err := r.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"none left: the kill switch (" + killSwitchPlace + ")\n",
		"none left: the route table's routes and policy rules, and its IPv6 leak guard\n",
		"none left: the OS's resolver configuration",
		"recorded: disconnected, as this boot's connect choice",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the report doesn't say %q:\n%s", want, out.String())
		}
	}
}

// A part that fails doesn't stop the others, nor the record; the report
// names what is left and the error says to run it again.
func TestRollbackTriesEveryPartWhateverFails(t *testing.T) {
	h := newDeadAgentHost()
	h.failDNS = errors.New("a backup it can't read")
	h.failKill = errors.New("nft refused")
	r, err := Rollback(h.platform())
	if !errors.Is(err, errRollbackLeft) {
		t.Fatalf("Rollback: %v, want errRollbackLeft", err)
	}
	for _, want := range []string{"route table held=true", "config overlay held=true", "DNS held=true", "kill switch held=true"} {
		if !strings.Contains(strings.Join(h.cleared, "\n"), want) {
			t.Errorf("not tried: %s; cleared: %q", want, h.cleared)
		}
	}
	if connect, ok, _ := h.rec.Load(); connect || !ok {
		t.Errorf("the connect choice is %v (recorded %v), want recorded down", connect, ok)
	}
	var out bytes.Buffer
	if err := r.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"LEFT: the OS's resolver configuration (what a crashed run changed, put back): a backup it can't read\n",
		"LEFT: the kill switch (" + killSwitchPlace + "): kill switch: nft refused\n",
		"none left: the overlay's routes\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the report doesn't say %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "traffic goes direct") {
		t.Errorf("the report says the host has no tunnel with parts left:\n%s", out.String())
	}
}
