package localapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
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

func (f *fakeMembership) lookup(ctx context.Context, uid, gid uint32) (bool, error) {
	return f.IsMember(ctx, uid, gid)
}

// xucred's 16 groups, none of them the API's.
var sixteenGroups = []uint32{20, 12, 61, 79, 80, 81, 98, 701, 33, 100, 204, 250, 395, 398, 399, 400}

func TestTheOSIsAskedAboutGroupsTheCallerDidntBring(t *testing.T) {
	ctx := context.Background()
	members := &fakeMembership{members: map[uint32]bool{1000: true}}
	p := Policy{ServiceUID: 990, Group: 50, HasGroup: true, Members: members}
	for _, tc := range []struct {
		name string
		c    Caller
		want Access
	}{
		{"a member past the first 16", Caller{UID: 1000, GIDs: sixteenGroups}, AccessControl},
		{"a member added since login", Caller{UID: 1000, GIDs: []uint32{20}}, AccessControl},
		{"not a member", Caller{UID: 1001, GIDs: sixteenGroups}, AccessNone},
	} {
		if got := p.Access(ctx, tc.c); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	members.asked = 0
	for _, c := range []Caller{{UID: 0}, {UID: 990}, {UID: 1001, GIDs: []uint32{50}}} {
		p.Access(ctx, c)
	}
	if members.asked != 0 {
		t.Errorf("asked %d times about callers the recorded credentials settle", members.asked)
	}
	if got := (Policy{ServiceUID: 990, Members: members}).Access(ctx, Caller{UID: 1000}); got != AccessNone || members.asked != 0 {
		t.Errorf("no group: got %v, asked %d times", got, members.asked)
	}

	failing := Policy{ServiceUID: 990, Group: 50, HasGroup: true, Members: &fakeMembership{members: map[uint32]bool{1000: true}, err: errors.New("no answer")}}
	if got, err := failing.access(ctx, Caller{UID: 1000, GIDs: sixteenGroups}); got != AccessNone || err == nil {
		t.Errorf("a failed lookup: got %v, %v; want none and the error", got, err)
	}
}

func TestMembershipLookupsAreBoundedAndKept(t *testing.T) {
	ctx := context.Background()
	f := &fakeMembership{members: map[uint32]bool{1000: true}}
	m := newCachedMembership(f.lookup)
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }

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
	now = now.Add(m.ttl)
	f.members[1000] = false
	if ok, _ := m.IsMember(ctx, 1000, 50); ok || f.asked != 3 {
		t.Errorf("after the ttl: member %v, asked %d times; want asked again", ok, f.asked)
	}

	f.err = errors.New("opendirectoryd is down")
	for range 2 {
		if ok, err := m.IsMember(ctx, 1002, 50); ok || err == nil {
			t.Errorf("a failed lookup: %v, %v; want not a member and the error", ok, err)
		}
	}
	if f.asked != 5 {
		t.Errorf("asked %d times; want a failure not kept", f.asked)
	}
	f.err = nil

	hung := newCachedMembership(func(ctx context.Context, _, _ uint32) (bool, error) {
		<-ctx.Done()
		return true, nil
	})
	hung.timeout = 20 * time.Millisecond
	start := time.Now()
	if ok, err := hung.IsMember(ctx, 1000, 50); ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a lookup past its timeout: %v, %v; want not a member", ok, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestMembershipCacheIsBounded(t *testing.T) {
	f := &fakeMembership{}
	m := newCachedMembership(f.lookup)
	for uid := range uint32(3 * membershipCacheMax) {
		_, _ = m.IsMember(context.Background(), uid, 50)
	}
	if n := len(m.answers); n > membershipCacheMax {
		t.Errorf("%d answers kept", n)
	}
}

// A refusal names the caller's uid, what the call needed and the group it
// was checked against, never the caller's groups.
func TestARefusalIsLoggedWithTheUIDAndTheGroup(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	p := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Members: &fakeMembership{err: errors.New("no answer")}}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: Caller{UID: 1001, GIDs: sixteenGroups}})
	if err := p.allow(ctx, log, localapiv1.LocalService_GetStatus_FullMethodName); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("got %v", err)
	}
	out := buf.String()
	for _, want := range []string{"local API call refused", "uid=1001", "group=4242", "needs=control", "recorded_groups=16", "no answer"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q lacks %q", out, want)
		}
	}
	if strings.Contains(out, "701") {
		t.Errorf("log %q lists the caller's groups", out)
	}

	buf.Reset()
	member := Policy{ServiceUID: 990, Group: 4242, HasGroup: true, Members: &fakeMembership{members: map[uint32]bool{1001: true}}}
	if err := member.allow(ctx, log, localapiv1.LocalService_GetStatus_FullMethodName); err != nil || buf.Len() != 0 {
		t.Errorf("a member by the OS: %v, logged %q", err, buf.String())
	}
	if err := member.allow(context.Background(), log, localapiv1.LocalService_GetStatus_FullMethodName); !errors.Is(err, ErrPermissionDenied) || !strings.Contains(buf.String(), "no peer credentials") {
		t.Errorf("no credentials: %v, logged %q", err, buf.String())
	}
}
