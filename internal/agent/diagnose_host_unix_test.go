//go:build unix

package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// deadAgentsHost is what a SIGKILLed device's agent left, as its readers
// report it: its routes, the guard and the kill switch with their pf
// references recorded, its resolver.
func deadAgentsHost() *inspected {
	ref := &routetable.PFReferenceReport{Recorded: true, Pid: 4242}
	return &inspected{
		routes: netcfg.Inspection{Routes: []netcfg.HostRoute{
			{Owner: netcfg.OwnerRouteTable, Family: netcfg.IPv4, Dst: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun7", Type: "unicast"},
			{Owner: netcfg.OwnerRouteTable, Family: netcfg.IPv6, Dst: netip.MustParsePrefix("::/0"), Type: "unreachable"},
		}},
		guard: routetable.GuardReport{Where: "pf anchor com.apple/000.thinkpol", Present: true, Exempt: []netip.Prefix{netip.MustParsePrefix("2001:db8:d0::/48")},
			PF: &routetable.PFReport{Enabled: true, GuardCheck: "hooked", Reference: ref}},
		killSwitch: firewall.KillSwitchReport{Where: "pf anchor com.apple/001.thinkpol-killswitch", Present: true,
			Sets: []firewall.KillSwitchSetReport{{Name: "allow4", Entries: 2}},
			PF:   &firewall.KillSwitchPFReport{Enabled: true, Reference: ref}},
		dns:     dns.HostReport{Sources: []dns.HostSource{{Name: "scutil --dns", Present: true, Resolvers: []dns.HostResolver{{Servers: []string{"100.64.0.53"}, NodeWritten: true}}}}},
		dropIns: DropInReport{Paths: []string{"/etc/systemd/system/thinkpol.service.d/override.conf"}},
	}
}

// Without the agent, the snapshot is the host's as the agent's own
// readers report it, every host part read once, and the crash trace a
// dead run left; the parts only the agent knows are unreadable, saying
// which of not running and not answering it was. No TUN is asked for:
// without the agent there is no name to ask.
func TestTheHostIsReadWithoutTheAgent(t *testing.T) {
	trace := filepath.Join(t.TempDir(), CrashTraceFile)
	if err := os.WriteFile(trace, []byte("panic: boom\n\ngoroutine 1 [running]:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for presence, why := range map[AgentPresence]string{AgentNotRunning: UnreadableAgentNotRunning, AgentNotAnswering: UnreadableAgentNotAnswering} {
		insp := deadAgentsHost()
		d := diagnoseHost(context.Background(), insp.inspector(), presence, trace)
		if d.Agent != presence || d.StatusUnreadable != why || !reflect.DeepEqual(d.TUN, netcfg.InterfaceReport{Unreadable: why}) ||
			d.LastApply.Unreadable != why || !d.HostParts || d.Status.Mode != "" {
			t.Fatalf("%s: %+v", presence, d)
		}
		if insp.reads() != 4 || len(insp.names()) != 0 {
			t.Fatalf("%s: %d host reads, interfaces asked %v", presence, insp.reads(), insp.names())
		}
		if !reflect.DeepEqual(d.Routes, insp.routes) || !reflect.DeepEqual(d.Guard, insp.guard) || !reflect.DeepEqual(d.KillSwitch, insp.killSwitch) ||
			!reflect.DeepEqual(d.DNS, insp.dns) || !reflect.DeepEqual(d.DropIns, insp.dropIns) {
			t.Fatalf("%s: the host parts aren't the readers':\n%+v", presence, d)
		}
		if d.LastRun.Trace != "panic: boom\n\ngoroutine 1 [running]:\n" || d.LastRun.Unreadable != "" || d.LastRun.Truncated {
			t.Fatalf("%s: last run %+v", presence, d.LastRun)
		}
	}
}

// The crash trace file is read as it is, never fixed, cut or emptied as
// a start does: none is no trace; one that is not a regular file of a
// single link is not read, and says so; a long one gives its head.
func TestTheTraceFileIsOnlyRead(t *testing.T) {
	dir := t.TempDir()
	if got := readLastRun(filepath.Join(dir, "none")); got != (LastRun{}) {
		t.Fatalf("no file: %+v", got)
	}

	long := filepath.Join(dir, "long")
	body := strings.Repeat("x", CrashTraceLimit+10)
	if err := os.WriteFile(long, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readLastRun(long)
	if len(got.Trace) != CrashTraceLimit || !got.Truncated || got.Unreadable != "" {
		t.Fatalf("a long trace: %d bytes, %v, %q", len(got.Trace), got.Truncated, got.Unreadable)
	}
	if fi, err := os.Stat(long); err != nil || fi.Size() != int64(len(body)) || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the file was changed: %v, %v", fi, err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(long, link); err != nil {
		t.Fatal(err)
	}
	if got := readLastRun(link); got.Unreadable == "" || got.Trace != "" {
		t.Fatalf("a symlink: %+v", got)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(long, hard); err != nil {
		t.Fatal(err)
	}
	if got := readLastRun(hard); !strings.Contains(got.Unreadable, "more than one link") || got.Trace != "" {
		t.Fatalf("a hard link: %+v", got)
	}
}

// No agent and no root: an error, and nothing of the host read.
func TestTheHostsSnapshotIsRoots(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	insp := deadAgentsHost()
	d, err := DiagnoseHost(context.Background(), insp.inspector(), AgentNotRunning, filepath.Join(t.TempDir(), CrashTraceFile))
	var needsRoot *NeedsRootError
	if !errors.Is(err, ErrDiagNeedsRoot) || !errors.As(err, &needsRoot) || !reflect.DeepEqual(d, Diagnostics{}) || insp.reads() != 0 {
		t.Fatalf("%+v, %v, %d reads", d, err, insp.reads())
	}
}
