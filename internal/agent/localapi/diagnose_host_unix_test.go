//go:build unix

package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// hostReader is a HostReader that records what it was asked and answers
// with a dead agent's leftovers: a guard and a kill switch still in pf,
// their references recorded.
type hostReader struct {
	mu    sync.Mutex
	asked []agent.AgentPresence
	err   error
}

func (h *hostReader) read(_ context.Context, presence agent.AgentPresence) (agent.Diagnostics, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = append(h.asked, presence)
	if h.err != nil {
		return agent.Diagnostics{}, h.err
	}
	why := agent.UnreadableAgentNotRunning
	if presence == agent.AgentNotAnswering {
		why = agent.UnreadableAgentNotAnswering
	}
	ref := &routetable.PFReferenceReport{Recorded: true, Pid: 4242}
	return agent.Diagnostics{
		Agent: presence, StatusUnreadable: why,
		TUN: netcfg.InterfaceReport{Unreadable: why}, LastApply: agent.ApplyReport{Unreadable: why},
		HostParts: true,
		Guard: routetable.GuardReport{Where: "pf anchor com.apple/000.thinkpol", Present: true,
			Rules: []routetable.GuardRuleReport{{Text: "block return out quick inet6 all"}},
			PF:    &routetable.PFReport{Enabled: true, GuardCheck: "hooked", Reference: ref}},
		KillSwitch: firewall.KillSwitchReport{Where: "pf anchor com.apple/001.thinkpol-killswitch", Present: true,
			Rules: []routetable.GuardRuleReport{{Text: "block return out quick all"}},
			PF:    &firewall.KillSwitchPFReport{Enabled: true, Reference: ref}},
		DNS:     dns.HostReport{Sources: []dns.HostSource{{Name: "scutil --dns", Present: true}}},
		LastRun: agent.LastRun{Trace: "panic: boom\n"},
	}, nil
}

func (h *hostReader) presences() []agent.AgentPresence {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.asked)
}

// snapshotJSON is d as diag prints it, parsed.
func snapshotJSON(t *testing.T, d *localapiv1.Diagnostics) (map[string]any, string) {
	t.Helper()
	var out bytes.Buffer
	if err := WriteDiagnostics(&out, d); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed, out.String()
}

// listenSilent is a socket whose listener does what answer does with
// each connection it accepts, never speaking gRPC.
func listenSilent(t *testing.T, answer func(net.Conn)) string {
	t.Helper()
	socket := filepath.Join(shortTempDir(t), "api.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			answer(c)
		}
	})
	return socket
}

// With no agent at the socket (none, or a dead one's left behind),
// root's diag is the host's snapshot, read without it: agent
// not_running, the status null with why, the TUN and last Apply
// unreadable for that reason, the host parts as read, and no error (the
// snapshot is all there is to take: exit 0).
func TestDiagWithoutAnAgentReadsTheHost(t *testing.T) {
	// A SIGKILLed agent's socket: the file is there, nothing listens.
	stale := filepath.Join(shortTempDir(t), "api.sock")
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	if _, err := os.Lstat(stale); err != nil {
		t.Fatal(err)
	}

	for name, socket := range map[string]string{"no socket": filepath.Join(shortTempDir(t), "none.sock"), "a dead agent's socket": stale} {
		t.Run(name, func(t *testing.T) {
			h := &hostReader{}
			before := time.Now()
			d, err := DiagnoseOrReadHost(context.Background(), socket, time.Minute, h.read, testVersion)
			if err != nil || d == nil {
				t.Fatalf("%v, %v", d, err)
			}
			if got := h.presences(); !slices.Equal(got, []agent.AgentPresence{agent.AgentNotRunning}) {
				t.Fatalf("asked %v", got)
			}
			if d.GetSchemaVersion() != SchemaVersion || d.GetAgentVersion() != testVersion || d.GetTakenAt().AsTime().Before(before.Truncate(time.Second)) {
				t.Fatalf("header: %v", d)
			}
			parsed, out := snapshotJSON(t, d)
			tun, _ := parsed["tun"].(map[string]any)
			apply, _ := parsed["last_apply"].(map[string]any)
			if parsed["agent"] != "not_running" || parsed["status"] != nil || parsed["status_unreadable"] != agent.UnreadableAgentNotRunning ||
				tun["unreadable"] != agent.UnreadableAgentNotRunning || apply["unreadable"] != agent.UnreadableAgentNotRunning ||
				parsed["host_parts"] != true || parsed["schema_version"] != float64(SchemaVersion) {
				t.Fatalf("JSON:\n%s", out)
			}
			// The dead agent's guard and kill switch: their anchors and
			// their recorded pf references.
			for part, anchor := range map[string]string{"guard": "pf anchor com.apple/000.thinkpol", "kill_switch": "pf anchor com.apple/001.thinkpol-killswitch"} {
				p, _ := parsed[part].(map[string]any)
				pf, _ := p["pf"].(map[string]any)
				ref, _ := pf["reference"].(map[string]any)
				if p["where"] != anchor || p["present"] != true || ref["recorded"] != true || ref["pid"] != float64(4242) {
					t.Errorf("%s:\n%s", part, out)
				}
			}
			if lr, _ := parsed["last_run"].(map[string]any); fmt.Sprint(lr["lines"]) != "[panic: boom]" {
				t.Errorf("last_run:\n%s", out)
			}
		})
	}
}

// A running agent's snapshot is its own, saying so: the host isn't read
// beside it.
func TestARunningAgentTakesTheSnapshot(t *testing.T) {
	s := serve(t, me())
	h := &hostReader{}
	d, err := DiagnoseOrReadHost(context.Background(), s.socket, time.Minute, h.read, "the CLI's")
	if err != nil {
		t.Fatal(err)
	}
	if got := h.presences(); len(got) != 0 {
		t.Fatalf("the host was read beside a running agent: %v", got)
	}
	parsed, out := snapshotJSON(t, d)
	if parsed["agent"] != "running" || parsed["status_unreadable"] != "" || parsed["status"] == nil || d.GetAgentVersion() != testVersion {
		t.Fatalf("JSON:\n%s", out)
	}
}

// Something holds the socket but gives no snapshot: in time (an agent
// that accepts and hangs), or at all (one that drops the connection).
// The host is read all the same, so the evidence is kept, and the error
// says the service didn't answer (exit 69): the snapshot is short of
// what a running agent gives.
func TestAnAgentThatDoesntAnswerStillLeavesTheHostsSnapshot(t *testing.T) {
	var held []net.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	hangs := listenSilent(t, func(c net.Conn) { mu.Lock(); held = append(held, c); mu.Unlock() })
	drops := listenSilent(t, func(c net.Conn) { _ = c.Close() })

	for name, socket := range map[string]string{"hangs": hangs, "drops the connection": drops} {
		t.Run(name, func(t *testing.T) {
			h := &hostReader{}
			start := time.Now()
			d, err := DiagnoseOrReadHost(context.Background(), socket, 300*time.Millisecond, h.read, testVersion)
			if !errors.Is(err, ErrServiceNotAnswering) || d == nil || !strings.Contains(err.Error(), "the thinkpol service is not answering") {
				t.Fatalf("%v, %v", d, err)
			}
			if took := time.Since(start); took > 15*time.Second {
				t.Errorf("took %s", took)
			}
			if got := h.presences(); !slices.Equal(got, []agent.AgentPresence{agent.AgentNotAnswering}) {
				t.Fatalf("asked %v", got)
			}
			parsed, out := snapshotJSON(t, d)
			if parsed["agent"] != "not_answering" || parsed["status"] != nil || parsed["status_unreadable"] != agent.UnreadableAgentNotAnswering {
				t.Fatalf("JSON:\n%s", out)
			}
		})
	}
}

// The host's snapshot is root's: a reader that refuses gives no
// snapshot, only its error, with the agent's silence beside it when
// there was one.
func TestNoSnapshotWhenTheHostCantBeRead(t *testing.T) {
	h := &hostReader{err: agent.ErrDiagNeedsRoot}
	d, err := DiagnoseOrReadHost(context.Background(), filepath.Join(shortTempDir(t), "none.sock"), time.Minute, h.read, testVersion)
	if d != nil || !errors.Is(err, agent.ErrDiagNeedsRoot) || errors.Is(err, ErrServiceNotAnswering) {
		t.Fatalf("no agent: %v, %v", d, err)
	}
	drops := listenSilent(t, func(c net.Conn) { _ = c.Close() })
	d, err = DiagnoseOrReadHost(context.Background(), drops, time.Minute, h.read, testVersion)
	if d != nil || !errors.Is(err, agent.ErrDiagNeedsRoot) || !errors.Is(err, ErrServiceNotAnswering) {
		t.Fatalf("an agent not answering: %v, %v", d, err)
	}
}

// A refusal by a running agent, and the caller giving up, are theirs:
// the host isn't read for them.
func TestARefusalOrTheCallersCancelReadsNoHost(t *testing.T) {
	h := &hostReader{}
	if os.Geteuid() != 0 {
		denied := serve(t, Policy{ServiceUID: uint32(os.Geteuid()) + 1})
		if d, err := DiagnoseOrReadHost(context.Background(), denied.socket, time.Minute, h.read, testVersion); d != nil || !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("refused: %v, %v", d, err)
		}
	}
	var held []net.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	hangs := listenSilent(t, func(c net.Conn) { mu.Lock(); held = append(held, c); mu.Unlock() })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if d, err := DiagnoseOrReadHost(ctx, hangs, time.Minute, h.read, testVersion); d != nil || err == nil || errors.Is(err, ErrServiceNotAnswering) {
		t.Fatalf("the caller gave up: %v, %v", d, err)
	}
	if got := h.presences(); len(got) != 0 {
		t.Fatalf("the host was read: %v", got)
	}
}

// A connection that can't be made in time, or a listener's backlog full
// (Linux's EAGAIN), is an agent not answering; a refused one (no
// listener) is not running, and anything else is neither.
func TestDialTimedOut(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "unix", Err: os.ErrDeadlineExceeded}
	for err, want := range map[error]bool{
		fmt.Errorf("connecting: %w", timeout): true,
		fmt.Errorf("connecting: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.EAGAIN)}): true,
		fmt.Errorf("connecting: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}): false,
		errors.New("something else"): false,
	} {
		if got := dialTimedOut(err); got != want {
			t.Errorf("%v: %v, want %v", err, got, want)
		}
	}
}
