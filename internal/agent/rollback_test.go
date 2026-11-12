package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// errNoServerHere is the supervisor's configurator in these tests: on
// Linux ClearLeftovers asks for it and fails before it touches the host;
// elsewhere a server has no part.
var errNoServerHere = errors.New("no supervisor's configurator in this test")

// deadAgentHost is a host a dead agent left: its route table's and
// overlay's routes, its resolver configuration, its kill switch and a
// connect choice recorded up. Each clear and each record notes whether it
// ran under the host lock.
type deadAgentHost struct {
	mu         sync.Mutex
	otherAgent bool     // another process holds the host lock
	held       bool     // this test's caller holds it
	cleared    []string // what was cleared or recorded, each "<what> held=<bool>"
	failDNS    error
	failKill   error
	failRecord error
	ks         memKillSwitches
	rec        memConnectRecord
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

func (h *deadAgentHost) notes() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.cleared, "\n")
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
	p.NewKillSwitch = func() KillSwitch { return notingKillSwitch{h: h, KillSwitch: h.ks.new()} }
	p.ConnectRecord = notingRecord{h}
	p.LockHost = func() (func(), error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.otherAgent || h.held {
			return nil, fmt.Errorf("%w (it holds the test's lock)", ErrAnotherAgent)
		}
		h.held = true
		return func() { h.mu.Lock(); h.held = false; h.mu.Unlock() }, nil
	}
	return p
}

// notingKillSwitch is the host's kill switch, whose Close notes it and
// fails with the host's failKill, leaving it in place.
type notingKillSwitch struct {
	KillSwitch
	h *deadAgentHost
}

func (k notingKillSwitch) Close() error {
	k.h.note("kill switch")
	if k.h.failKill != nil {
		return k.h.failKill
	}
	return k.KillSwitch.Close()
}

// notingRecord is the host's connect record, whose Save notes it and
// fails with the host's failRecord, keeping what was recorded.
type notingRecord struct{ h *deadAgentHost }

func (r notingRecord) Load() (bool, bool, error) { return r.h.rec.Load() }

func (r notingRecord) Save(connect bool) error {
	r.h.note(fmt.Sprintf("record %v", connect))
	if r.h.failRecord != nil {
		return r.h.failRecord
	}
	return r.h.rec.Save(connect)
}

// clearedUnderTheLock are the notes of a rollback that recorded down,
// then cleared every device part, under the host lock.
var clearedUnderTheLock = []string{"record false held=true", "route table held=true", "config overlay held=true", "DNS held=true", "kill switch held=true"}

// tried checks that every part was tried, after the record, under the
// lock.
func (h *deadAgentHost) tried(t *testing.T) {
	t.Helper()
	notes := h.notes()
	if !strings.HasPrefix(notes, clearedUnderTheLock[0]+"\n") {
		t.Errorf("not recorded first, under the lock:\n%s", notes)
	}
	for _, want := range clearedUnderTheLock[1:] {
		if !strings.Contains(notes, want) {
			t.Errorf("not cleared under the lock: %s; noted:\n%s", want, notes)
		}
	}
}

// serverPartErr is the error the server's part ends with in these tests:
// errNoServerHere where a server runs, else none (no such part).
func serverPartErr(t *testing.T, r *RollbackReport) error {
	t.Helper()
	if r == nil || len(r.Parts) == 0 {
		t.Fatalf("the report has no parts: %+v", r)
	}
	if canServe := supported(ModeServer) == nil; r.Parts[0].server != canServe {
		t.Fatalf("a server's part in the report: %v, want %v (where a server runs)", r.Parts[0].server, canServe)
	}
	if !r.Parts[0].server {
		return nil
	}
	if !errors.Is(r.Parts[0].Err, errNoServerHere) {
		t.Fatalf("the server's part: %v, want the test's refusal", r.Parts[0].Err)
	}
	return r.Parts[0].Err
}

// While another process holds the host lock, rollback is refused and
// touches nothing: the running agent's routes, resolvers, kill switch and
// connect choice stay as they are, and there is no report.
func TestRollbackIsRefusedWhileAnotherProcessHoldsTheHost(t *testing.T) {
	h := newDeadAgentHost()
	h.otherAgent = true
	r, err := rollback(h.platform(), t.TempDir())
	var refused rollbackRefused
	if !errors.Is(err, ErrAnotherAgent) || !errors.As(err, &refused) || !strings.Contains(err.Error(), "another thinkpol process holds the host") {
		t.Fatalf("rollback: %v, want ErrAnotherAgent, refused", err)
	}
	if r != nil || h.notes() != "" {
		t.Errorf("refused, it still cleared or recorded %q (report %+v)", h.notes(), r)
	}
	if h.ks.rules() == nil {
		t.Error("refused, it removed the running agent's kill switch")
	}
	var out bytes.Buffer
	if err := r.Print(&out); err != nil || out.Len() > 0 {
		t.Errorf("refused, the report says %q (%v), want nothing", out.String(), err)
	}
	if connect, ok, _ := h.rec.Load(); !connect || !ok {
		t.Errorf("refused, the connect choice is %v (recorded %v), want up as the running agent left it", connect, ok)
	}
}

// Rollback records the boot's connect choice down, then clears each part
// a dead agent left, all under the host lock, so the service's next start
// doesn't put the crash posture's kill switch back.
func TestRollbackRecordsDownThenClearsWhatADeadAgentLeft(t *testing.T) {
	h := newDeadAgentHost()
	r, err := rollback(h.platform(), t.TempDir())
	var want error
	if serverPartErr(t, r) != nil {
		want = errRollbackLeft
	}
	if !errors.Is(err, want) || (want == nil) != (err == nil) || errors.Is(err, errRollbackNotRecorded) {
		t.Errorf("rollback: %v, want %v", err, want)
	}
	for _, p := range r.Parts {
		if p.Err != nil && !p.server {
			t.Errorf("%s: %v", p.What, p.Err)
		}
	}
	h.tried(t)
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
	if err := r.Print(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"none left: the kill switch (" + firewall.KillSwitchPlace + ")\n",
		"none left: the route table's routes and policy rules, and its IPv6 leak guard\n",
		"none left: the OS's resolver configuration",
		"recorded: disconnected, as this boot's connect choice",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the report doesn't say %q:\n%s", want, out.String())
		}
	}
}

// A part that fails doesn't stop the others; the report names what is
// left, each part once, and the error says to run it again.
func TestRollbackTriesEveryPartWhateverFails(t *testing.T) {
	h := newDeadAgentHost()
	h.failDNS = errors.New("a backup it can't read")
	h.failKill = errors.New("nft refused")
	r, err := rollback(h.platform(), t.TempDir())
	_ = serverPartErr(t, r)
	if err == nil || err.Error() != errRollbackLeft.Error() {
		t.Fatalf("rollback: %v, want only errRollbackLeft", err)
	}
	h.tried(t)
	if connect, ok, _ := h.rec.Load(); connect || !ok {
		t.Errorf("the connect choice is %v (recorded %v), want recorded down", connect, ok)
	}
	var out bytes.Buffer
	if err := r.Print(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"LEFT: the OS's resolver configuration (what a crashed run changed, put back): a backup it can't read\n",
		"LEFT: the kill switch (" + firewall.KillSwitchPlace + "): nft refused\n",
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

// ClearHost, as `service uninstall` runs it, names each part left once,
// the server's last.
func TestClearHostNamesEachPartLeftOnce(t *testing.T) {
	h := newDeadAgentHost()
	h.failDNS = errors.New("a backup it can't read")
	h.failKill = errors.New("nft refused")
	_, err := h.platform().ClearHost()
	want := "the OS's resolver configuration (what a crashed run changed, put back): a backup it can't read\n" +
		"the kill switch (" + firewall.KillSwitchPlace + "): nft refused"
	server := supported(ModeServer) == nil
	if server {
		want += "\na server's leftovers (the spaces' veths, the forwarding its supervisor turned on, its nftables tables): "
	}
	if err == nil || server && (!strings.HasPrefix(err.Error(), want) || !strings.HasSuffix(err.Error(), errNoServerHere.Error())) ||
		!server && err.Error() != want {
		t.Errorf("ClearHost: %v\nwant %s", err, want)
	}
	if !errors.Is(err, h.failKill) || !errors.Is(err, h.failDNS) || server != errors.Is(err, errNoServerHere) {
		t.Errorf("ClearHost: %v doesn't wrap what failed", err)
	}
}

// A record that can't be saved doesn't stop the clearing: every part is
// still tried, and the error says the choice wasn't recorded.
func TestRollbackWhoseRecordFailsStillClearsEveryPart(t *testing.T) {
	h := newDeadAgentHost()
	h.failRecord = errors.New("a read-only /run")
	r, err := rollback(h.platform(), t.TempDir())
	want := errRollbackNotRecorded.Error()
	if serverPartErr(t, r) != nil {
		want = errRollbackLeft.Error() + "\n" + want
	}
	if !errors.Is(err, errRollbackNotRecorded) || err.Error() != want {
		t.Fatalf("rollback: %v, want %s", err, want)
	}
	h.tried(t)
	if h.ks.rules() != nil {
		t.Error("the kill switch is still in place")
	}
	if !errors.Is(r.RecordErr, h.failRecord) {
		t.Errorf("the report's record error: %v", r.RecordErr)
	}
}

// The report says per part what is left, how the choice was recorded,
// and, with nothing left, that traffic goes direct and what a service's
// next start changes of that, for the node's mode and kill-switch toggle;
// its error says what is left, or that the choice wasn't recorded.
func TestTheRollbackReportSaysWhatIsLeftAndWhatComesNext(t *testing.T) {
	const (
		dns      = "none left: the OS's resolver configuration\n"
		ks       = "none left: the kill switch (the table)\n"
		recorded = "recorded: disconnected, as this boot's connect choice: a service's next start in this boot comes up disconnected (`thinkpol connect` connects it again)\n"
		direct   = "the host has no tunnel: traffic goes direct"
	)
	clear := []HostPart{{What: "the OS's resolver configuration"}, {What: "the kill switch (the table)"}}
	left := []HostPart{{What: "the OS's resolver configuration"}, {What: "the kill switch (the table)", Err: errors.New("nft refused")}}
	server := []HostPart{{What: "a server's leftovers", Undone: []string{"the space link tp-space1"}, server: true}, clear[0], clear[1]}
	readOnly := errors.New("a read-only /run")
	for _, c := range []struct {
		name string
		r    *RollbackReport
		out  string
		err  []error
	}{
		{"refused", nil, "", nil},
		{"clear, toggle off", &RollbackReport{Parts: clear}, dns + ks + recorded +
			direct + ", and stays so at a service's next start in this boot: the kill switch's toggle is off\n", nil},
		{"clear, toggle on", &RollbackReport{Parts: clear, next: nextStart{killSwitch: true}}, dns + ks + recorded +
			direct + " until a service's next start in this boot puts the kill switch back, in the down shape: its toggle is on (`thinkpol kill-switch off` once the agent runs)\n", nil},
		{"clear, settings unreadable", &RollbackReport{Parts: clear, next: nextStart{err: errors.New("no state directory")}}, dns + ks + recorded +
			direct + "; a service's next start in this boot puts the kill switch back, in the down shape, if its toggle is on (the node's settings can't be read: no state directory)\n", nil},
		{"a part left", &RollbackReport{Parts: left}, dns + "LEFT: the kill switch (the table): nft refused\n" + recorded, []error{errRollbackLeft}},
		{"not recorded", &RollbackReport{Parts: clear, RecordErr: readOnly}, dns + ks +
			"NOT RECORDED: this boot's connect choice: a read-only /run; a service's next start in this boot may connect and put the kill switch back\n" +
			direct + "\n", []error{errRollbackNotRecorded}},
		{"a part left, not recorded", &RollbackReport{Parts: left, RecordErr: readOnly}, dns + "LEFT: the kill switch (the table): nft refused\n" +
			"NOT RECORDED: this boot's connect choice: a read-only /run; a service's next start in this boot may connect and put the kill switch back\n",
			[]error{errRollbackLeft, errRollbackNotRecorded}},
		{"a server", &RollbackReport{Parts: server, next: nextStart{server: true}},
			"undid: the space link tp-space1\nnone left: a server's leftovers\n" + dns + ks +
				"recorded: disconnected, as this boot's connect choice; a server's start doesn't read it\n" +
				direct + " until a service's next start runs the server again\n", nil},
		{"a server, not recorded", &RollbackReport{Parts: clear, RecordErr: readOnly, next: nextStart{server: true}}, dns + ks +
			"not recorded: this boot's connect choice: a read-only /run; a server's start doesn't read it\n" +
			direct + " until a service's next start runs the server again\n", nil},
	} {
		var out bytes.Buffer
		if err := c.r.Print(&out); err != nil {
			t.Fatal(err)
		}
		if out.String() != c.out {
			t.Errorf("%s: the report says\n%s\nwant\n%s", c.name, out.String(), c.out)
		}
		if c.r == nil {
			continue
		}
		if got, want := c.r.err(), errors.Join(c.err...); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: error %v, want %v", c.name, got, want)
		}
	}
}

// The report's next start is read from the node's state directory: a
// server where its map shows one, else the device's kill-switch toggle,
// the member's over the node file's.
func TestRollbackReadsTheNextStartFromTheNode(t *testing.T) {
	s := newTestSpace(t)
	device := s.stateDir(t, s.b, 1)
	if got := readNextStart(device); got != (nextStart{}) {
		t.Errorf("a device with no toggle set: %+v", got)
	}
	writeFile(t, filepath.Join(device, NodeFile), []byte(`{"kill_switch": true}`), 0o600)
	if got := readNextStart(device); got != (nextStart{killSwitch: true}) {
		t.Errorf("the node file's toggle on: %+v", got)
	}
	writeFile(t, filepath.Join(device, DeviceFile), []byte(`{"kill_switch": false}`), 0o600)
	if got := readNextStart(device); got != (nextStart{}) {
		t.Errorf("the member's toggle off over the node file's on: %+v", got)
	}
	if got := readNextStart(s.stateDir(t, s.a, 1)); got != (nextStart{server: true}) {
		t.Errorf("a server's: %+v", got)
	}
	if got := readNextStart(filepath.Join(t.TempDir(), "none")); got.err == nil {
		t.Errorf("no state directory: %+v, want an error", got)
	}
}

// A start whose agent was prepared (its process started by the
// service manager) while the dead agent's connect choice still said up,
// and that takes the host lock only after a rollback recorded it down,
// comes up disconnected and puts no kill switch back: it decides under
// the lock, not as it was prepared.
func TestAStartPreparedBeforeARollbackFollowsTheRollback(t *testing.T) {
	s := newTestSpace(t)
	_, reg := memoryRegistry(t)
	h := newDeadAgentHost()
	plat := h.platform()
	plat.Transports = func(bool) (*transport.Registry, error) { return reg, nil }
	cfg := testConfig(s.stateDir(t, s.b, 1))
	cfg.Service, cfg.FailClosedAfterCrash = true, true
	n, err := Prepare(cfg, Logs{}, plat)
	if err != nil {
		t.Fatal(err)
	}
	n.device.Rules.Preset = rules.PresetEverything

	if r, err := rollback(plat, t.TempDir()); err != nil && serverPartErr(t, r) == nil {
		t.Fatalf("rollback: %v", err)
	}
	h.tried(t)

	adapters, err := n.Adapters(nil)
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	for _, a := range adapters {
		if a.Name == "node" {
			go func() { done <- a.Run(ctx) }()
		}
	}
	eventually(t, func() bool { return n.Status().KillSwitch.Error != KillSwitchNotApplied })
	if st := n.Status(); st.Connection != Disconnected {
		t.Errorf("the start after the rollback: %s, want disconnected", st.Connection)
	}
	if r := h.ks.rules(); r != nil {
		t.Errorf("the start after the rollback put the kill switch back: %+v", r)
	}
	if connect, ok, _ := h.rec.Load(); connect || !ok {
		t.Errorf("the connect choice is %v (recorded %v), want down as rollback recorded it", connect, ok)
	}
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
}
