package localapi

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// LOCAL_PEERCRED gives the peer's uid and its groups, the effective one
// first: what every call is checked by. A Unix socket in a temporary
// directory, nothing else.
func TestPeerCredentialsAreTheCallers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	caller, err := callerOf(c)
	if err != nil {
		t.Fatal(err)
	}
	if caller.UID != uint32(os.Geteuid()) || len(caller.GIDs) == 0 || caller.GIDs[0] != uint32(os.Getegid()) {
		t.Errorf("caller %+v; want uid %d, groups starting with %d", caller, os.Geteuid(), os.Getegid())
	}
}

func TestDsclOutputIsParsed(t *testing.T) {
	if gid, ok := parsePrimaryGroupID("PrimaryGroupID: 701\n"); !ok || gid != 701 {
		t.Errorf("%d %v", gid, ok)
	}
	for _, bad := range []string{"", "No such key: PrimaryGroupID\n", "PrimaryGroupID: x\n"} {
		if _, ok := parsePrimaryGroupID(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, ok := systemGroup("../etc"); ok {
		t.Error("a path as a group name")
	}
}
