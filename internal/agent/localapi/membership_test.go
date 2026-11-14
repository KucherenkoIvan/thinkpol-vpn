package localapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KucherenkoIvan/go-kernel/grpckit"
	"google.golang.org/grpc/peer"

	localapiv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/localapi/v1"
)

// fakeMembership answers from a set of members, or fails with err, and
// counts what it was asked.
type fakeMembership struct {
	mu      sync.Mutex
	members map[uint32]bool
	err     error
	asked   int
}

func (f *fakeMembership) IsMember(_ context.Context, uid, _ uint32) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	return f.members[uid], f.err
}

// membershipFunc is a Membership that is a function.
type membershipFunc func(ctx context.Context, uid, gid uint32) (bool, error)

func (f membershipFunc) IsMember(ctx context.Context, uid, gid uint32) (bool, error) {
	return f(ctx, uid, gid)
}

// xucred's 16 groups, none of them the API's; 987654 appears nowhere else,
// so a log that has it lists the groups.
var sixteenGroups = []uint32{20, 12, 61, 79, 80, 81, 98, 987654, 33, 100, 204, 250, 395, 398, 399, 400}

func TestTheOSIsAskedAboutGroupsTheCallerDidntBring(t *testing.T) {
	ctx := context.Background()
	members := &fakeMembership{members: map[uint32]bool{1000: true}}
	p := Policy{ServiceUID: 990, Group: 50, HasGroup: true, Membership: members}
	for _, tc := range []struct {
		name string
		c    Caller
		want Access
	}{
		{"a member past the first 16", Caller{UID: 1000, GIDs: sixteenGroups}, AccessControl},
		{"a member added since login", Caller{UID: 1000, GIDs: []uint32{20}}, AccessControl},
		{"not a member", Caller{UID: 1001, GIDs: sixteenGroups}, AccessNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := p.access(ctx, tc.c); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheOSIsNotAskedWhenTheCredentialsSettleIt(t *testing.T) {
	ctx := context.Background()
	members := &fakeMembership{members: map[uint32]bool{1000: true}}
	p := Policy{ServiceUID: 990, Group: 50, HasGroup: true, Membership: members}
	for _, c := range []Caller{{UID: 0}, {UID: 990}, {UID: 1001, GIDs: []uint32{50}}} {
		_, _ = p.access(ctx, c)
	}
	if members.asked != 0 {
		t.Errorf("asked %d times about callers the recorded credentials settle", members.asked)
	}
	if got, _ := (Policy{ServiceUID: 990, Membership: members}).access(ctx, Caller{UID: 1000}); got != AccessNone || members.asked != 0 {
		t.Errorf("no group: got %v, asked %d times", got, members.asked)
	}
}

func TestAFailedLookupIsNotAMember(t *testing.T) {
	failing := Policy{ServiceUID: 990, Group: 50, HasGroup: true, Membership: &fakeMembership{members: map[uint32]bool{1000: true}, err: errors.New("no answer")}}
	if got, err := failing.access(context.Background(), Caller{UID: 1000, GIDs: sixteenGroups}); got != AccessNone || err == nil {
		t.Errorf("got %v, %v; want none and the error", got, err)
	}
}

// fakeClock is a settable now.
func fakeClock(m *cachedMembership) *time.Time {
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	return &now
}

func TestMembershipAnswersAreKept(t *testing.T) {
	ctx := context.Background()
	f := &fakeMembership{members: map[uint32]bool{1000: true}}
	m := newCachedMembership(f)
	now := fakeClock(m)
	for range 3 {
		if ok, err := m.IsMember(ctx, 1000, 50); !ok || err != nil {
			t.Fatalf("member: %v, %v", ok, err)
		}
		if ok, err := m.IsMember(ctx, 1001, 50); ok || err != nil {
			t.Fatalf("not a member: %v, %v", ok, err)
		}
	}
	if f.asked != 2 {
		t.Errorf("asked %d times; want each answer kept", f.asked)
	}
	*now = now.Add(m.ttl)
	f.members[1000] = false
	if ok, _ := m.IsMember(ctx, 1000, 50); ok || f.asked != 3 {
		t.Errorf("after the ttl: member %v, asked %d times; want asked again", ok, f.asked)
	}
}

// While Directory Services is down, callers are refused at once, and it
// is asked again soon after.
func TestMembershipFailuresAreKeptBriefly(t *testing.T) {
	ctx := context.Background()
	f := &fakeMembership{members: map[uint32]bool{1002: true}, err: errors.New("opendirectoryd is down")}
	m := newCachedMembership(f)
	now := fakeClock(m)
	for range 3 {
		if ok, err := m.IsMember(ctx, 1002, 50); ok || err == nil || !strings.Contains(err.Error(), "opendirectoryd is down") {
			t.Errorf("a failed lookup: %v, %v; want not a member and the error", ok, err)
		}
	}
	if f.asked != 1 {
		t.Errorf("asked %d times; want the failure kept", f.asked)
	}
	*now = now.Add(m.failureTTL)
	f.err = nil
	if ok, err := m.IsMember(ctx, 1002, 50); !ok || err != nil || f.asked != 2 {
		t.Errorf("after the failure's ttl: %v, %v, asked %d times; want asked again", ok, err, f.asked)
	}
	// Longer than a lookup may take, so that a steady poller is mostly
	// answered at once; shorter than an answer.
	if m.failureTTL <= m.timeout || m.failureTTL >= m.ttl {
		t.Errorf("a failure kept %v, an answer %v, a lookup's timeout %v", m.failureTTL, m.ttl, m.timeout)
	}
}

func TestAHungMembershipLookupIsCutOff(t *testing.T) {
	hung := newCachedMembership(membershipFunc(func(ctx context.Context, _, _ uint32) (bool, error) {
		<-ctx.Done()
		return true, nil
	}))
	hung.timeout = 20 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		ok, err := hung.IsMember(context.Background(), 1000, 50)
		if ok {
			err = errors.New("a member")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a lookup past its timeout: %v; want not a member, timed out", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("a hung lookup wasn't cut off")
	}
}

// A caller that hangs up mid-lookup stops waiting, and the lookup runs on
// for the next caller: what Directory Services says doesn't depend on who
// asked, and an impatient poller would otherwise never fill the cache.
func TestAnAbandonedMembershipLookupIsKept(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	m := newCachedMembership(membershipFunc(func(ctx context.Context, _, _ uint32) (bool, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	if ok, err := m.IsMember(ctx, 1000, 50); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned: %v, %v", ok, err)
	}
	close(release)
	if ok, err := m.IsMember(context.Background(), 1000, 50); !ok || err != nil || calls.Load() != 1 {
		t.Errorf("the next caller: %v, %v after %d lookups; want the abandoned one's answer", ok, err, calls.Load())
	}
}

// Many callers at once fork one dsmemberutil: the others wait and take its
// answer.
func TestMembershipLookupsRunOneAtATime(t *testing.T) {
	release := make(chan struct{})
	var running, peak, calls atomic.Int32
	m := newCachedMembership(membershipFunc(func(context.Context, uint32, uint32) (bool, error) {
		calls.Add(1)
		n := running.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		running.Add(-1)
		return true, nil
	}))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if ok, err := m.IsMember(context.Background(), 1000, 50); !ok || err != nil {
				t.Errorf("a waiter: %v, %v", ok, err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if peak.Load() != 1 {
		t.Errorf("%d lookups at once; want 1", peak.Load())
	}
	if calls.Load() != 1 {
		t.Errorf("%d lookups; want 1 (the waiters take its answer)", calls.Load())
	}
}

func TestAMembershipWaiterThatLeavesStopsWaiting(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	m := newCachedMembership(membershipFunc(func(context.Context, uint32, uint32) (bool, error) {
		close(started)
		<-release
		return true, nil
	}))
	go func() { _, _ = m.IsMember(context.Background(), 1000, 50) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := m.IsMember(ctx, 1001, 50)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("a waiter that left: %v; want canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("a waiter that left still waits for the lookup slot")
	}
}

func TestMembershipCacheIsBounded(t *testing.T) {
	f := &fakeMembership{}
	m := newCachedMembership(f)
	for uid := range uint32(3 * membershipCacheMax) {
		_, _ = m.IsMember(context.Background(), uid, 50)
	}
	if n := len(m.answers); n > membershipCacheMax {
		t.Errorf("%d answers kept", n)
	}
}

// A full cache drops the expired answers first and keeps the fresh ones.
func TestAFullMembershipCacheDropsTheExpired(t *testing.T) {
	ctx := context.Background()
	f := &fakeMembership{}
	m := newCachedMembership(f)
	now := fakeClock(m)
	for uid := range uint32(membershipCacheMax - 1) {
		_, _ = m.IsMember(ctx, uid, 50)
	}
	*now = now.Add(m.ttl)
	fresh := uint32(membershipCacheMax)
	_, _ = m.IsMember(ctx, fresh, 50)   // the cache is full now
	_, _ = m.IsMember(ctx, fresh+1, 50) // the expired go
	asked := f.asked
	_, _ = m.IsMember(ctx, fresh, 50)
	if f.asked != asked {
		t.Errorf("a fresh answer was dropped with the expired ones")
	}
	if n := len(m.answers); n != 2 {
		t.Errorf("%d answers kept; want the 2 fresh ones", n)
	}
}

// refusalLog is a text log without the time, which could hold any digits.
func refusalLog(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
}

func callerCtx(c Caller) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: c})
}

// A refusal names the caller's uid, what the call needed and the group it
// was checked against, never the caller's groups.
func TestARefusalIsLoggedWithTheUIDAndTheGroup(t *testing.T) {
	var buf bytes.Buffer
	p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: &fakeMembership{}}
	ctx := callerCtx(Caller{UID: 1001, GIDs: sixteenGroups})
	if err := p.allow(ctx, refusalLog(&buf), localapiv1.LocalService_GetStatus_FullMethodName); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("got %v", err)
	}
	out := buf.String()
	for _, want := range []string{"level=INFO", "local API call refused", "refusal=permission_denied", "uid=1001", "group=4242", "needs=control", "has=none", "recorded_groups=16"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q lacks %q", out, want)
		}
	}
	if strings.Contains(out, "987654") {
		t.Errorf("log %q lists the caller's groups", out)
	}
}

func TestAnAllowedCallIsNotLogged(t *testing.T) {
	var buf bytes.Buffer
	member := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: &fakeMembership{members: map[uint32]bool{1001: true}}}
	if err := member.allow(callerCtx(Caller{UID: 1001, GIDs: sixteenGroups}), refusalLog(&buf), localapiv1.LocalService_GetStatus_FullMethodName); err != nil || buf.Len() != 0 {
		t.Errorf("a member by the OS: %v, logged %q", err, buf.String())
	}
}

func TestACallWithoutCredentialsIsRefused(t *testing.T) {
	var buf bytes.Buffer
	p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: &fakeMembership{members: map[uint32]bool{1001: true}}}
	if err := p.allow(context.Background(), refusalLog(&buf), localapiv1.LocalService_GetStatus_FullMethodName); !errors.Is(err, ErrPermissionDenied) || !strings.Contains(buf.String(), "no peer credentials") {
		t.Errorf("no credentials: %v, logged %q", err, buf.String())
	}
}

// Each refusal says which case it is: a caller asking for root's call, a
// stranger, or a caller the OS couldn't place.
func TestRefusalsSayWhy(t *testing.T) {
	down := &fakeMembership{err: errors.New("opendirectoryd is down")}
	timedOut := &fakeMembership{err: fmt.Errorf("no answer within 3s: %w", context.DeadlineExceeded)}
	ok := &fakeMembership{members: map[uint32]bool{1001: true}}
	status := localapiv1.LocalService_GetStatus_FullMethodName
	for _, tc := range []struct {
		name    string
		members Membership
		gids    []uint32
		method  string
		want    Error
		inLog   []string
	}{
		{"a member asks for the log", ok, []uint32{4242}, localapiv1.LocalService_TailLogs_FullMethodName, ErrRootOnly, []string{"level=INFO", "refusal=root_only", "needs=admin"}},
		{"a stranger asks for the status", &fakeMembership{}, sixteenGroups, status, ErrPermissionDenied, []string{"level=INFO", "refusal=permission_denied", "has=none"}},
		{"asking the OS fails, for the status", down, sixteenGroups, status, ErrMembershipCheckFailed, []string{"level=WARN", "refusal=membership_check_failed", "opendirectoryd is down"}},
		{"the OS doesn't answer in time", timedOut, sixteenGroups, status, ErrMembershipUnknown, []string{"level=WARN", "refusal=membership_unknown", "no answer within"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: tc.members}
			err := p.allow(callerCtx(Caller{UID: 1001, GIDs: tc.gids}), refusalLog(&buf), tc.method)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if wantPerm := tc.want != ErrMembershipUnknown && tc.want != ErrMembershipCheckFailed; IsPermission(err) != wantPerm {
				t.Errorf("IsPermission(%v) = %v", err, !wantPerm)
			}
			for _, want := range tc.inLog {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("log %q lacks %q", buf.String(), want)
				}
			}
		})
	}
}

// No group grants root's call, so the OS isn't asked about it, and the
// refusal doesn't depend on whether it could answer.
func TestARootCallIsRefusedWithoutAskingTheOS(t *testing.T) {
	for _, members := range []*fakeMembership{{members: map[uint32]bool{1001: true}}, {}, {err: errors.New("opendirectoryd is down")}} {
		var buf bytes.Buffer
		p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: members}
		err := p.allow(callerCtx(Caller{UID: 1001, GIDs: sixteenGroups}), refusalLog(&buf), localapiv1.LocalService_TailLogs_FullMethodName)
		if !errors.Is(err, ErrRootOnly) || members.asked != 0 {
			t.Errorf("%+v: %v, asked %d times; want root_only, not asked", members, err, members.asked)
		}
		if out := buf.String(); !strings.Contains(out, "refusal=root_only") || strings.Contains(out, "has=") {
			t.Errorf("log %q: want root_only, without what wasn't looked up", out)
		}
	}
}

// A caller that hangs up, or whose own deadline passes, while the OS is
// asked isn't refused, and its leaving isn't logged as the OS failing.
func TestACallerThatLeftIsNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		leave func(parent context.Context, asked <-chan struct{}) (context.Context, context.CancelFunc)
		want  error
	}{
		{"it hangs up", func(parent context.Context, asked <-chan struct{}) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			go func() {
				<-asked
				cancel()
			}()
			return ctx, cancel
		}, context.Canceled},
		// A deadline isn't a cancel: judging by context.Canceled would
		// report this one as the OS failing.
		{"its deadline passes", func(parent context.Context, _ <-chan struct{}) (context.Context, context.CancelFunc) {
			return context.WithTimeout(parent, 20*time.Millisecond)
		}, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			asked, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			hung := newCachedMembership(membershipFunc(func(ctx context.Context, _, _ uint32) (bool, error) {
				close(asked)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return false, errors.New("opendirectoryd is down")
			}))
			p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: hung}
			ctx, cancel := tc.leave(callerCtx(Caller{UID: 1001, GIDs: sixteenGroups}), asked)
			defer cancel()
			err := p.allow(ctx, refusalLog(&buf), localapiv1.LocalService_GetStatus_FullMethodName)
			if !errors.Is(err, tc.want) || errors.Is(err, ErrMembershipUnknown) || errors.Is(err, ErrMembershipCheckFailed) {
				t.Errorf("got %v; want %v, no refusal", err, tc.want)
			}
			if strings.Contains(buf.String(), "level=WARN") || strings.Contains(buf.String(), "refused") {
				t.Errorf("logged %q", buf.String())
			}
		})
	}
}

// Every refusal has its wording, a detailed one with the verb its detail
// fills, and none of the wording points at the log, which only root may
// read. The permission refusals and service_down keep their prefixes;
// the dial-time refusal says what the per-call one says.
func TestRefusalWording(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range refusals {
		if r.err.code == "" || seen[r.err.code] {
			t.Errorf("refusal %q: empty or listed twice", r.err.code)
		}
		seen[r.err.code] = true
		if r.msg == "" || r.detailed != strings.Contains(r.msg, "%") {
			t.Errorf("%s: wording %q, detailed %v", r.err.code, r.msg, r.detailed)
		}
		if strings.Contains(r.msg, "log") {
			t.Errorf("points at root's log: %q", r.msg)
		}
	}
	for _, e := range []Error{ErrPermissionDenied, ErrRootOnly} {
		if !strings.HasPrefix(refusalMsg(e, ""), "permission denied") {
			t.Errorf("%s: %q", e.code, refusalMsg(e, ""))
		}
	}
	if msg := refusalMsg(ErrServiceDown, ""); !strings.HasPrefix(msg, "the thinkpol service") {
		t.Errorf("service_down: %q", msg)
	}
	err := dialError("x.sock", &net.OpError{Op: "dial", Err: os.ErrPermission})
	if !errors.Is(err, ErrPermissionDenied) || !strings.HasPrefix(err.Error(), refusalMsg(ErrPermissionDenied, "")) || !strings.Contains(err.Error(), "x.sock") {
		t.Errorf("dial: %v", err)
	}
}

// No refusal code exists outside the list: every Error literal in the
// package is a value declared at the top of errors.go, each of them a
// row of refusals (Refusals), or the one withDetail builds from one of
// them; and nothing outside errors.go sets a code. An Error built or
// changed anywhere else would reach a client, and the CLI's exit table,
// as a code nothing names. An Error literal is one of any type whose
// underlying type is Error (an alias, or a type defined from it), and
// any literal with a code key (an element whose type is elided).
func TestEveryRefusalIsDeclaredInTheList(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = f
	}
	errorTypes := errorTypeNames(files)
	isError := func(lit *ast.CompositeLit) bool {
		if id, ok := lit.Type.(*ast.Ident); ok && errorTypes[id.Name] {
			return true
		}
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "code" {
					return true
				}
			}
		}
		return false
	}
	declared := map[string]bool{}
	for name, f := range files {
		allowed := map[*ast.CompositeLit]bool{}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if name != "errors.go" || d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					for _, v := range spec.(*ast.ValueSpec).Values {
						if lit, ok := v.(*ast.CompositeLit); ok && isError(lit) {
							allowed[lit] = true
							declared[literalCode(t, fset, lit)] = true
						}
					}
				}
			case *ast.FuncDecl:
				if name == "errors.go" && d.Name.Name == "withDetail" && d.Recv != nil {
					ast.Inspect(d, func(n ast.Node) bool {
						if lit, ok := n.(*ast.CompositeLit); ok && isError(lit) {
							allowed[lit] = true
						}
						return true
					})
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if isError(n) && !allowed[n] {
					t.Errorf("%s: an Error built outside the refusals declared in errors.go", fset.Position(n.Pos()))
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if isCodeField(lhs) && name != "errors.go" {
						t.Errorf("%s: a code set outside errors.go", fset.Position(lhs.Pos()))
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND && isCodeField(n.X) && name != "errors.go" {
					t.Errorf("%s: a code's address taken outside errors.go", fset.Position(n.Pos()))
				}
			}
			return true
		})
	}
	listed := map[string]bool{}
	for _, e := range Refusals() {
		listed[e.code] = true
		if !declared[e.code] {
			t.Errorf("Refusals has %s, which errors.go doesn't declare", e.code)
		}
	}
	for code := range declared {
		if !listed[code] {
			t.Errorf("refusal %s is declared but not in refusals", code)
		}
	}
}

// errorTypeNames are Error and every type in files, at any scope, whose
// underlying type is Error: an alias of it or a type defined from it,
// directly or through another such type.
func errorTypeNames(files map[string]*ast.File) map[string]bool {
	var specs []*ast.TypeSpec
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.TypeSpec); ok {
				specs = append(specs, s)
			}
			return true
		})
	}
	names := map[string]bool{"Error": true}
	for grew := true; grew; {
		grew = false
		for _, s := range specs {
			typ := s.Type
			for {
				p, ok := typ.(*ast.ParenExpr)
				if !ok {
					break
				}
				typ = p.X
			}
			if id, ok := typ.(*ast.Ident); ok && names[id.Name] && !names[s.Name.Name] {
				names[s.Name.Name] = true
				grew = true
			}
		}
	}
	return names
}

// isCodeField reports whether x is a selector of a field named code
// (e.code). Only errors.go may set one: Error's and the refusals rows'
// are the package's only code fields.
func isCodeField(x ast.Expr) bool {
	for {
		p, ok := x.(*ast.ParenExpr)
		if !ok {
			break
		}
		x = p.X
	}
	sel, ok := x.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "code"
}

// The client finds each refusal in what the server sends, with a detail
// or without, so none reaches a caller as a bare code; a code that isn't
// a refusal stays no refusal.
func TestTheClientFindsEveryRefusalInItsCode(t *testing.T) {
	c := &Client{}
	for _, e := range Refusals() {
		for _, code := range []string{e.code, e.code + ":tun"} {
			err := c.explain(&grpckit.RemoteDomainError{Code: code})
			var got Error
			if !errors.As(err, &got) || got != e {
				t.Errorf("%s: %v, want %s", code, err, e.code)
			}
		}
	}
	if err := c.explain(&grpckit.RemoteDomainError{Code: "start_failed:tun"}); !strings.Contains(err.Error(), `step "tun"`) {
		t.Errorf("start_failed:tun says %q", err)
	}
	var e Error
	if err := c.explain(&grpckit.RemoteDomainError{Code: "made_up"}); errors.As(err, &e) {
		t.Errorf("made_up is the refusal %s", e.code)
	}
}

// literalCode is a declared refusal's code: Error{code: "..."}.
func literalCode(t *testing.T, fset *token.FileSet, lit *ast.CompositeLit) string {
	t.Helper()
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if b, ok := kv.Value.(*ast.BasicLit); ok && b.Kind == token.STRING {
				if code, err := strconv.Unquote(b.Value); err == nil {
					return code
				}
			}
		}
	}
	t.Errorf("%s: a declared refusal without a literal code", fset.Position(lit.Pos()))
	return ""
}
