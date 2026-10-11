//go:build linux && !android

package supervisor_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	iflaTargetNetnsID = 0x2e // IFLA_TARGET_NETNSID
	iflaIfname        = 0x3  // IFLA_IFNAME
	iflaLinkinfo      = 0x12 // IFLA_LINKINFO
	iflaInfoKind      = 0x1  // IFLA_INFO_KIND
	nsGetUserns       = 0xb701
)

// escapeAttempt tries, from inside a worker, to reach the root namespace
// through the veth's link-netnsid: it creates a dummy interface in the peer's
// network namespace (the root namespace), addressing it by the netns id the
// kernel assigned to the veth's peer. It needs CAP_NET_ADMIN over the root
// namespace's owning user namespace; confined to its own user namespace, a
// worker doesn't have it and the kernel refuses with EPERM/EACCES, while a
// process in the initial user namespace succeeds. It returns nil when the
// operation was permitted (the escape worked).
func escapeAttempt(name string) error {
	link, err := netlink.LinkByName("veth0")
	if err != nil {
		return fmt.Errorf("veth0: %w", err)
	}
	nsid := link.Attrs().NetNsID
	if nsid < 0 {
		return fmt.Errorf("no peer netns id to target")
	}
	return createDummyInNetns(int32(nsid), name)
}

// createDummyInNetns sends RTM_NEWLINK to create a dummy interface in the
// network namespace identified by nsid (relative to the current one).
func createDummyInNetns(nsid int32, name string) error {
	nbo := binary.NativeEndian
	ifinfo := make([]byte, 16) // ifinfomsg, all zero (family AF_UNSPEC, no index)

	attr := func(typ uint16, val []byte) []byte {
		a := make([]byte, 4+len(val))
		nbo.PutUint16(a[0:], uint16(4+len(val)))
		nbo.PutUint16(a[2:], typ)
		copy(a[4:], val)
		for len(a)%4 != 0 {
			a = append(a, 0)
		}
		return a
	}
	nsidAttr := make([]byte, 4)
	nbo.PutUint32(nsidAttr, uint32(nsid))
	kind := attr(iflaInfoKind, []byte("dummy"))
	linkinfo := attr(iflaLinkinfo, kind)

	body := append(ifinfo, attr(iflaTargetNetnsID, nsidAttr)...)
	body = append(body, attr(iflaIfname, append([]byte(name), 0))...)
	body = append(body, linkinfo...)

	return rtnetlinkAck(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// rtnetlinkAck sends one acknowledged rtnetlink request and returns the
// kernel's error, nil on success.
func rtnetlinkAck(msgType, extraFlags int, body []byte) error {
	nbo := binary.NativeEndian
	s, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(s) }()
	if err := unix.Bind(s, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	msg := make([]byte, 16+len(body))
	nbo.PutUint32(msg[0:], uint32(len(msg)))
	nbo.PutUint16(msg[4:], uint16(msgType))
	nbo.PutUint16(msg[6:], uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK|extraFlags))
	nbo.PutUint32(msg[8:], 1) // seq
	copy(msg[16:], body)
	if err := unix.Sendto(s, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	resp := make([]byte, 8192)
	n, _, err := unix.Recvfrom(s, resp, 0)
	if err != nil {
		return err
	}
	if n < 20 {
		return fmt.Errorf("short netlink reply (%d bytes)", n)
	}
	if typ := nbo.Uint16(resp[4:]); typ != unix.NLMSG_ERROR {
		return fmt.Errorf("unexpected netlink reply type %d", typ)
	}
	if errno := int32(nbo.Uint32(resp[16:])); errno != 0 {
		return unix.Errno(-errno)
	}
	return nil
}

// nsIno is the "dev:inode" identity of a namespace file.
func nsIno(t *testing.T, path string) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

// netnsOwnerOf returns the identity of the user namespace that owns pid's
// network namespace. A worker's network namespace is owned by its own
// (non-initial) user namespace, so its NET_ADMIN can't reach the root
// namespace.
func netnsOwnerOf(t *testing.T, pid int) string {
	t.Helper()
	f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		t.Fatalf("open netns of %d: %v", pid, err)
	}
	defer func() { _ = f.Close() }()
	ufd, err := unix.IoctlRetInt(int(f.Fd()), nsGetUserns)
	if err != nil {
		t.Fatalf("NS_GET_USERNS: %v", err)
	}
	owner := os.NewFile(uintptr(ufd), "owner-userns")
	defer func() { _ = owner.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(owner.Fd()), &st); err != nil {
		t.Fatalf("fstat owner userns: %v", err)
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}
