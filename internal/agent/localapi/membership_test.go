package localapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	if m.failureTTL >= m.ttl {
		t.Errorf("a failure kept %v, an answer %v", m.failureTTL, m.ttl)
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

// A caller that hangs up mid-lookup leaves nothing behind for the next.
func TestAnAbandonedMembershipLookupIsNotKept(t *testing.T) {
	var calls atomic.Int32
	m := newCachedMembership(membershipFunc(func(ctx context.Context, _, _ uint32) (bool, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return false, ctx.Err()
		}
		return true, nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	if ok, err := m.IsMember(ctx, 1000, 50); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned: %v, %v", ok, err)
	}
	if ok, err := m.IsMember(context.Background(), 1000, 50); !ok || err != nil || calls.Load() != 2 {
		t.Errorf("the next caller: %v, %v after %d lookups; want a fresh one", ok, err, calls.Load())
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

// Each refusal says which case it is: a member asking for root's call, a
// stranger, or a caller the OS couldn't place.
func TestRefusalsSayWhy(t *testing.T) {
	down := &fakeMembership{err: errors.New("opendirectoryd is down")}
	ok := &fakeMembership{members: map[uint32]bool{1001: true}}
	logs := localapiv1.LocalService_TailLogs_FullMethodName
	status := localapiv1.LocalService_GetStatus_FullMethodName
	for _, tc := range []struct {
		name    string
		members Membership
		method  string
		want    Error
		inLog   []string
	}{
		{"a member asks for the log", ok, logs, ErrRootOnly, []string{"level=INFO", "refusal=root_only", "has=control"}},
		{"a stranger asks for the status", &fakeMembership{}, status, ErrPermissionDenied, []string{"level=INFO", "refusal=permission_denied"}},
		{"the OS can't say, for the status", down, status, ErrMembershipUnknown, []string{"level=WARN", "refusal=membership_unknown", "opendirectoryd is down"}},
		{"the OS can't say, for the log", down, logs, ErrRootOnly, []string{"refusal=root_only", "opendirectoryd is down"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Membership: tc.members}
			err := p.allow(callerCtx(Caller{UID: 1001, GIDs: sixteenGroups}), refusalLog(&buf), tc.method)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if wantPerm := tc.want != ErrMembershipUnknown; IsPermission(err) != wantPerm {
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

// The refusals a person reads point nowhere they can't go, and the
// dial-time refusal says what the per-call one says.
func TestRefusalWording(t *testing.T) {
	for _, e := range []Error{ErrPermissionDenied, ErrRootOnly, ErrMembershipUnknown} {
		msg := refusalMsg(e)
		if msg == e.Code || strings.Contains(msg, "log says") || strings.Contains(msg, "logs") {
			t.Errorf("%s: %q", e.Code, msg)
		}
	}
	if !strings.Contains(refusalMsg(ErrMembershipUnknown), "try again") {
		t.Errorf("membership unknown: %q", refusalMsg(ErrMembershipUnknown))
	}
	err := dialError("x.sock", &net.OpError{Op: "dial", Err: os.ErrPermission})
	if !errors.Is(err, ErrPermissionDenied) || !strings.HasPrefix(err.Error(), refusalMsg(ErrPermissionDenied)) || !strings.Contains(err.Error(), "x.sock") {
		t.Errorf("dial: %v", err)
	}
}
