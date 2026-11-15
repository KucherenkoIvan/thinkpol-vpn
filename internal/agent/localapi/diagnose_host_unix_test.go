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

// listenStopped is a socket whose listener never accepts, as a
// stopped (SIGSTOP) agent's: the kernel completes each connection into
// the backlog, and nothing ever reads it.
func listenStopped(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(shortTempDir(t), "api.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return socket
}

// lockedBuffer is a bytes.Buffer safe to write from another goroutine.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
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
			d, err := DiagnoseOrReadHost(context.Background(), socket, time.Minute, h.read, testVersion, nil)
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
	var waiting lockedBuffer
	d, err := DiagnoseOrReadHost(context.Background(), s.socket, time.Minute, h.read, "the CLI's", &waiting)
	if err != nil {
		t.Fatal(err)
	}
	if said := waiting.String(); said != "" {
		t.Errorf("an agent that answered was said to be waited on: %q", said)
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
// that accepts and hangs, or a stopped one, SIGSTOP, whose socket the
// kernel still connects without it ever accepting), or at all (one that
// drops the connection). The host is read all the same, so the evidence
// is kept, and the error says the service didn't answer (exit 69): the
// snapshot is short of what a running agent gives. While it waits on a
// silent agent, diag says so; asked again once the host is read, the
// silent agent still doesn't answer, so the snapshot stays not_answering.
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
	stopped := listenStopped(t)

	for _, row := range []struct {
		name   string
		socket string
		says   bool
	}{
		{"hangs", hangs, true},
		{"stopped, never accepts", stopped, true},
		{"drops the connection", drops, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			h := &hostReader{}
			var waiting lockedBuffer
			start := time.Now()
			d, err := DiagnoseOrReadHost(context.Background(), row.socket, 300*time.Millisecond, h.read, testVersion, &waiting)
			if !errors.Is(err, ErrServiceNotAnswering) || errors.Is(err, ErrServiceRestarted) || d == nil || !strings.Contains(err.Error(), "the thinkpol service is not answering") {
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
			if said := waiting.String(); row.says && (strings.Count(said, "\n") != 1 || !strings.Contains(said, "waiting up to") || !strings.Contains(said, row.socket)) {
				t.Errorf("waiting on a silent agent said %q", said)
			}
		})
	}
}

// An agent that answers once the host has been read (launchd restarted
// the dead one during the read, or the silent one came back) is said:
// the snapshot is agent restarted_during_read, with
// ErrServiceRestarted (exit 69), never a dead run's not_running (0),
// since the new agent may have put the host back while it was read.
func TestAnAgentThatComesUpDuringTheReadIsSaid(t *testing.T) {
	var held []net.Conn
	var mu sync.Mutex
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	for _, row := range []struct {
		name string
		// at is the socket diag dials, and gone what was there before.
		at  func(t *testing.T) (at string, gone func())
		was agent.AgentPresence
	}{
		{"was not running", func(t *testing.T) (string, func()) {
			return filepath.Join(shortTempDir(t), "api.sock"), func() {}
		}, agent.AgentNotRunning},
		{"was not answering", func(t *testing.T) (string, func()) {
			socket := filepath.Join(shortTempDir(t), "api.sock")
			l, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					mu.Lock()
					held = append(held, c)
					mu.Unlock()
				}
			}()
			return socket, func() { _ = l.Close() }
		}, agent.AgentNotAnswering},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := serve(t, me())
			at, gone := row.at(t)
			h := &hostReader{}
			// The new agent's socket appears at the dialled path while the
			// host is read.
			read := func(ctx context.Context, p agent.AgentPresence) (agent.Diagnostics, error) {
				gone()
				if err := os.Rename(s.socket, at); err != nil {
					t.Fatal(err)
				}
				return h.read(ctx, p)
			}
			d, err := DiagnoseOrReadHost(context.Background(), at, 300*time.Millisecond, read, testVersion, nil)
			if !errors.Is(err, ErrServiceRestarted) || errors.Is(err, ErrServiceNotAnswering) || d == nil {
				t.Fatalf("%v, %v", d, err)
			}
			if got := h.presences(); !slices.Equal(got, []agent.AgentPresence{row.was}) {
				t.Fatalf("asked %v", got)
			}
			parsed, out := snapshotJSON(t, d)
			if parsed["agent"] != "restarted_during_read" || parsed["status"] != nil || parsed["host_parts"] != true {
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
	d, err := DiagnoseOrReadHost(context.Background(), filepath.Join(shortTempDir(t), "none.sock"), time.Minute, h.read, testVersion, nil)
	if d != nil || !errors.Is(err, agent.ErrDiagNeedsRoot) || errors.Is(err, ErrServiceNotAnswering) {
		t.Fatalf("no agent: %v, %v", d, err)
	}
	drops := listenSilent(t, func(c net.Conn) { _ = c.Close() })
	d, err = DiagnoseOrReadHost(context.Background(), drops, time.Minute, h.read, testVersion, nil)
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
		if d, err := DiagnoseOrReadHost(context.Background(), denied.socket, time.Minute, h.read, testVersion, nil); d != nil || !errors.Is(err, ErrPermissionDenied) {
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
	if d, err := DiagnoseOrReadHost(ctx, hangs, time.Minute, h.read, testVersion, nil); d != nil || err == nil || errors.Is(err, ErrServiceNotAnswering) {
		t.Fatalf("the caller gave up: %v, %v", d, err)
	}
	if got := h.presences(); len(got) != 0 {
		t.Fatalf("the host was read: %v", got)
	}
}

// A connection that can't be made in time, or a listener's backlog full
// (Linux's EAGAIN), is an agent not answering; a refused one (no
// listener) is not running, and anything else is neither.
func TestATimedOutDialOrAFullBacklogIsNotAnswering(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "unix", Err: os.ErrDeadlineExceeded}
	for err, want := range map[error]bool{
		fmt.Errorf("connecting: %w", timeout): true,
		fmt.Errorf("connecting: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.EAGAIN)}):       true,
		fmt.Errorf("connecting: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}): false,
		errors.New("something else"): false,
	} {
		if got := dialTimedOut(err); got != want {
			t.Errorf("%v: %v, want %v", err, got, want)
		}
	}
}
