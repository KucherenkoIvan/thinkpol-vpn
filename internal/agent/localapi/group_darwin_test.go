package localapi

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

func TestDsmemberutilIsAskedByNumbers(t *testing.T) {
	var got []string
	answer, fail := "user is a member of the group\n", error(nil)
	lookup := dsmemberutil(func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte(answer), fail
	})
	if ok, err := lookup(context.Background(), 501, 701); !ok || err != nil {
		t.Errorf("member: %v, %v", ok, err)
	}
	if want := []string{"/usr/bin/dsmemberutil", "checkmembership", "-u", "501", "-g", "701"}; !slices.Equal(got, want) {
		t.Errorf("ran %q, want %q", got, want)
	}
	answer = "user is not a member of the group\n"
	if ok, err := lookup(context.Background(), 501, 701); ok || err != nil {
		t.Errorf("not a member: %v, %v", ok, err)
	}
	for _, bad := range []struct {
		out string
		err error
	}{
		{"user is a member of the group\n", errors.New("exit status 6")},
		{"ID supplied was not a number\n", nil},
		{"", nil},
		{"user is a member of the group, maybe\n", nil},
	} {
		answer, fail = bad.out, bad.err
		if ok, err := lookup(context.Background(), 501, 701); ok || err == nil {
			t.Errorf("%q, %v: %v, %v; want not a member and an error", bad.out, bad.err, ok, err)
		}
	}
}

// The real Directory Services, read only: this user is in its own primary
// group, and in no group that doesn't exist.
func TestDirectoryServicesAnswers(t *testing.T) {
	m := systemMembership()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if ok, err := m.IsMember(context.Background(), uid, gid); !ok || err != nil {
		t.Errorf("uid %d in its group %d: %v, %v", uid, gid, ok, err)
	}
	if ok, err := m.IsMember(context.Background(), uid, 4242424); ok || err != nil {
		t.Errorf("uid %d in a group that doesn't exist: %v, %v", uid, ok, err)
	}
}
