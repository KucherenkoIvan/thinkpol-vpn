//go:build unix

package localapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/go-kernel/grpckit"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/logring"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// fakeNode is a node whose state the test sets.
type fakeNode struct {
	mu         sync.Mutex
	st         agent.Status
	connectErr error
}

func (n *fakeNode) Status() agent.Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.st
}

func (n *fakeNode) Connect(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.connectErr != nil {
		return n.connectErr
	}
	n.st.Connection = agent.Connected
	n.st.DataPlane = &dataplane.Status{MTU: 1328, IPv6: true, Egresses: []router.EgressStatus{{Name: "overlay", MTU: 1328}}}
	return nil
}

func (n *fakeNode) Disconnect(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.st.Connection, n.st.DataPlane = agent.Disconnected, nil
	return nil
}

// shortTempDir is a temporary directory short enough for a socket path
// (macOS allows about 104 bytes).
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "tpapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

type served struct {
	socket string
	node   *fakeNode
	logs   *logring.Ring
	stop   context.CancelFunc
	done   chan error
}

func serve(t *testing.T, p Policy) *served {
	t.Helper()
	s := &served{
		socket: filepath.Join(shortTempDir(t), "api", "api.sock"),
		node:   &fakeNode{st: agent.Status{Mode: agent.ModeDevice, Space: netmap.SpaceID{0xab, 1}, MapVersion: 7}},
		logs:   logring.New(1 << 16),
		done:   make(chan error, 1),
	}
	l, err := Listen(s.socket, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	srv := NewGRPCServer(ctx, Options{Node: s.node, Logs: s.logs, Log: slog.New(slog.DiscardHandler)}, p)
	go func() { s.done <- grpckit.Serve(ctx, srv, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(15 * time.Second):
			t.Error("the server didn't stop")
		}
	})
	return s
}

func dial(t *testing.T, socket string) *Client {
	t.Helper()
	c, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func me() Policy { return Policy{ServiceUID: uint32(os.Geteuid())} }

func TestTheCLIControlsTheNode(t *testing.T) {
	s := serve(t, me())
	c := dial(t, s.socket)
	ctx := context.Background()

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.GetConnection() != localapiv1.Connection_CONNECTION_DISCONNECTED || st.GetMapVersion() != 7 ||
		st.GetSpaceId() != (netmap.SpaceID{0xab, 1}).String() || st.GetHealth().GetLevel() != localapiv1.HealthLevel_HEALTH_LEVEL_DOWN {
		t.Fatalf("status %v", st)
	}
	if st, err = c.Connect(ctx); err != nil || st.GetConnection() != localapiv1.Connection_CONNECTION_CONNECTED || st.GetDataPlane().GetMtu() != 1328 {
		t.Fatalf("connect: %v, %v", st, err)
	}
	var out bytes.Buffer
	if err := WriteStatus(&out, st, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`state: +connected`, `health: +ok`, "map version 7", "mtu 1328, ipv6 on", `overlay \(mtu 1328\)`} {
		if !regexp.MustCompile(want).MatchString(out.String()) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}
	if st, err = c.Disconnect(ctx); err != nil || st.GetConnection() != localapiv1.Connection_CONNECTION_DISCONNECTED {
		t.Fatalf("disconnect: %v, %v", st, err)
	}

	spaces, err := c.Spaces(ctx)
	if err != nil || len(spaces) != 1 || !spaces[0].GetActive() || spaces[0].GetId() != st.GetSpaceId() {
		t.Fatalf("spaces %v, %v", spaces, err)
	}
	if err := c.SetRulePreset(ctx, "everything"); !errors.Is(err, ErrPresetsUnavailable) {
		t.Fatalf("got %v, want ErrPresetsUnavailable", err)
	}

	s.node.mu.Lock()
	s.node.connectErr = &agent.StartError{Step: agent.StepTUN, Err: errors.New("detail 192.0.2.1 for the log only")}
	s.node.mu.Unlock()
	if _, err := c.Connect(ctx); err == nil || !strings.Contains(err.Error(), `step "tun"`) || strings.Contains(err.Error(), "192.0.2.1") {
		t.Fatalf("got %v, want the step and no detail", err)
	}
	s.node.mu.Lock()
	s.node.connectErr = agent.ErrServerMode
	s.node.mu.Unlock()
	if _, err := c.Connect(ctx); !errors.Is(err, ErrServerMode) {
		t.Fatalf("got %v, want ErrServerMode", err)
	}
}

func TestStreamsFollowAndEndOnShutdown(t *testing.T) {
	s := serve(t, me())
	c := dial(t, s.socket)
	for i := range 150 {
		_, _ = s.logs.Write([]byte("line " + string(rune('a'+i%26)) + "\n"))
	}
	var got []string
	if err := c.TailLogs(context.Background(), 10, false, func(lines []string, _ uint64) error {
		got = append(got, lines...)
		return nil
	}); err != nil || len(got) != 10 || got[9] != "line t" {
		t.Fatalf("last 10: %q, %v", got, err)
	}

	follow := make(chan []string, 16)
	followed := make(chan error, 1)
	go func() {
		followed <- c.TailLogs(context.Background(), 1, true, func(lines []string, _ uint64) error {
			follow <- lines
			return nil
		})
	}()
	if l := <-follow; !slices.Equal(l, []string{"line t"}) {
		t.Fatalf("first %q", l)
	}
	_, _ = s.logs.Write([]byte("fresh \x1b[31mred\n"))
	select {
	case l := <-follow:
		if !slices.Equal(l, []string{`fresh \x1b[31mred`}) {
			t.Fatalf("followed %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no new line")
	}

	statuses := make(chan *localapiv1.Status, 16)
	watched := make(chan error, 1)
	go func() {
		watched <- c.WatchStatus(context.Background(), time.Millisecond, func(st *localapiv1.Status) error {
			statuses <- st
			return nil
		})
	}()
	for range 2 {
		select {
		case <-statuses:
		case <-time.After(5 * time.Second):
			t.Fatal("no status")
		}
	}

	// A stop ends both streams cleanly, without waiting out a grace period.
	start := time.Now()
	s.stop()
	for _, ch := range []chan error{followed, watched} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("stream ended with %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a stream outlived the service")
		}
	}
	if err := <-s.done; err != nil {
		t.Fatal(err)
	}
	s.done <- nil
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stopping took %v", d)
	}
	if _, err := os.Lstat(s.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}

func TestEverythingTheServiceSaysIsSanitized(t *testing.T) {
	s := serve(t, me())
	c := dial(t, s.socket)
	s.node.st.Workers = []agent.WorkerStatus{{Space: netmap.SpaceID{1}, Ready: true, Starts: 1}}
	s.node.st.PublicListeners = []agent.PublicListenerStatus{{Transport: "udp\x1b]0;pwned\x07\u202e"}}
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := st.GetPublicListeners()[0].GetTransport(); got != `udp\x1b]0;pwned\x07\u202e` {
		t.Fatalf("transport %q", got)
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{ServiceUID: 990, Group: 50, HasGroup: true}
	for _, tc := range []struct {
		c    Caller
		want Access
	}{
		{Caller{UID: 0}, AccessAdmin},
		{Caller{UID: 990, GIDs: []uint32{990}}, AccessAdmin},
		{Caller{UID: 1000, GIDs: []uint32{1000, 50}}, AccessControl},
		{Caller{UID: 1000, GIDs: []uint32{50}}, AccessControl},
		{Caller{UID: 1001, GIDs: []uint32{1001, 51}}, AccessNone},
	} {
		if got := p.Access(tc.c); got != tc.want {
			t.Errorf("%+v: got %d, want %d", tc.c, got, tc.want)
		}
	}
	if got := (Policy{ServiceUID: 990}).Access(Caller{UID: 1000, GIDs: []uint32{50}}); got != AccessNone {
		t.Errorf("no group: got %d", got)
	}

	for group, want := range map[string]Policy{
		"":                           {ServiceUID: uint32(os.Geteuid())},
		"no-such-group-for-thinkpol": {ServiceUID: uint32(os.Geteuid())},
		"4242":                       {ServiceUID: uint32(os.Geteuid()), Group: 4242, HasGroup: true},
	} {
		if got, err := NewPolicy(group); err != nil || got != want {
			t.Errorf("NewPolicy(%q) = %+v, %v; want %+v", group, got, err, want)
		}
	}
}

// Over a real socket, by this process's real credentials: a stranger gets
// nothing, a member of the group controls but doesn't read the log.
func TestCallersAreCheckedByTheirCredentials(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may do everything")
	}
	ctx := context.Background()
	stranger := serve(t, Policy{ServiceUID: uint32(os.Geteuid()) + 1})
	c := dial(t, stranger.socket)
	if _, err := c.Status(ctx); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("stranger's status: %v", err)
	}
	err := c.TailLogs(ctx, 1, false, func([]string, uint64) error { return nil })
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("stranger's logs: %v", err)
	}

	member := serve(t, Policy{ServiceUID: uint32(os.Geteuid()) + 1, Group: uint32(os.Getegid()), HasGroup: true})
	c = dial(t, member.socket)
	if _, err := c.Connect(ctx); err != nil {
		t.Fatalf("member's connect: %v", err)
	}
	err = c.TailLogs(ctx, 1, false, func([]string, uint64) error { return nil })
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("member's logs: %v", err)
	}
}

func TestListenOwnsItsDirectory(t *testing.T) {
	gid := os.Getegid()
	for _, tc := range []struct {
		p              Policy
		dirMode, sMode os.FileMode
	}{
		{me(), 0o700, 0o600},
		{Policy{ServiceUID: uint32(os.Geteuid()), Group: uint32(gid), HasGroup: true}, 0o750, 0o660},
	} {
		path := filepath.Join(shortTempDir(t), "api", "api.sock")
		l, err := Listen(path, tc.p)
		if err != nil {
			t.Fatal(err)
		}
		for p, want := range map[string]os.FileMode{filepath.Dir(path): tc.dirMode, path: tc.sMode} {
			fi, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != want || int(fi.Sys().(*syscall.Stat_t).Gid) != gid {
				t.Errorf("%s: mode %v gid %d, want %v gid %d", p, fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid, want, gid)
			}
		}
		// Another service on the same socket is refused.
		if _, err := Listen(path, tc.p); err == nil || !strings.Contains(err.Error(), "another service") {
			t.Fatalf("second Listen: %v", err)
		}
		_ = l.Close()
	}

	// A crashed service's socket is replaced.
	path := filepath.Join(shortTempDir(t), "api", "api.sock")
	l, err := Listen(path, me())
	if err != nil {
		t.Fatal(err)
	}
	l.(interface{ SetUnlinkOnClose(bool) }).SetUnlinkOnClose(false)
	_ = l.Close()
	if l, err = Listen(path, me()); err != nil {
		t.Fatalf("over a stale socket: %v", err)
	}
	_ = l.Close()

	// A directory it didn't make the way it would is refused, not fixed.
	dir := filepath.Join(shortTempDir(t), "api")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(dir, "api.sock"), me()); err == nil {
		t.Fatal("took a directory others can enter")
	}
	if fi, _ := os.Lstat(dir); fi.Mode().Perm() != 0o755 {
		t.Fatalf("changed it to %v", fi.Mode().Perm())
	}
	// So is a file that isn't a socket.
	dir = filepath.Join(shortTempDir(t), "api")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(dir, "api.sock"), me()); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("over a file: %v", err)
	}
}

func TestDialExplainsWhyNot(t *testing.T) {
	if _, err := Dial(filepath.Join(shortTempDir(t), "none.sock")); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("no service: %v", err)
	}
	if os.Geteuid() == 0 {
		return
	}
	s := serve(t, me())
	dir := filepath.Dir(s.socket)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if _, err := Dial(s.socket); !errors.Is(err, ErrPermissionDenied) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("no access: %v", err)
	}
}
