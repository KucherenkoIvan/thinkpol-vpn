//go:build linux && !android

package supervisor_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// escapeAttempt tries, from inside a worker, to reach the root namespace
// through the veth's link-netnsid: it sets an interface alias on the veth's
// peer, which lives in the root network namespace, addressing it by the
// peer's ifindex and the netns id the kernel assigned. It needs CAP_NET_ADMIN
// over the root namespace's owning user namespace. Confined to its own user
// namespace, a worker doesn't have it and the kernel returns EPERM; a worker
// left in the initial user namespace (the bug this guards) would succeed.
//
// It returns nil when the operation was permitted (the escape worked).
func escapeAttempt() error {
	link, err := netlink.LinkByName("veth0")
	if err != nil {
		return fmt.Errorf("veth0: %w", err)
	}
	nsid := link.Attrs().NetNsID
	// The peer's ifindex, as seen in the peer (root) namespace; sysfs is
	// reliable where netlink's ParentIndex may be 0.
	peer := link.Attrs().ParentIndex
	if b, err := os.ReadFile("/sys/class/net/veth0/iflink"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			peer = v
		}
	}
	if nsid < 0 || peer == 0 {
		return fmt.Errorf("no peer netns id (%d) or ifindex (%d) to target", nsid, peer)
	}
	return setPeerAlias(int32(nsid), int32(peer), "escaped-by-worker")
}

const (
	iflaTargetNetnsID = 0x2e
	iflaIfAlias       = 0x14
	nsGetUserns       = 0xb701 // NS_GET_USERNS
)

// nsID is the "dev:inode" identity of a namespace file.
func nsID(path string) string {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "err"
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

// netnsOwnerUserns is the identity of the user namespace that owns this
// process's network namespace. A worker's network namespace is owned by its
// own (non-initial) user namespace, so its CAP_NET_ADMIN can't reach the root
// namespace.
func netnsOwnerUserns() string {
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return "err"
	}
	defer func() { _ = f.Close() }()
	ufd, err := unix.IoctlRetInt(int(f.Fd()), nsGetUserns)
	if err != nil {
		return "err:" + err.Error()
	}
	owner := os.NewFile(uintptr(ufd), "owner-userns")
	defer func() { _ = owner.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(owner.Fd()), &st); err != nil {
		return "err"
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

// setPeerAlias sends RTM_SETLINK for a link in another network namespace
// (addressed by netns id), setting its alias.
func setPeerAlias(nsid, ifindex int32, alias string) error {
	nbo := binary.NativeEndian
	ifinfo := make([]byte, 16)
	nbo.PutUint32(ifinfo[4:], uint32(ifindex)) // ifi_index

	attrs := make([]byte, 0, 32)
	nsidAttr := make([]byte, 8)
	nbo.PutUint16(nsidAttr[0:], 8)
	nbo.PutUint16(nsidAttr[2:], iflaTargetNetnsID)
	nbo.PutUint32(nsidAttr[4:], uint32(nsid))
	attrs = append(attrs, nsidAttr...)

	val := append([]byte(alias), 0)
	aliasAttr := make([]byte, 4+len(val))
	nbo.PutUint16(aliasAttr[0:], uint16(4+len(val)))
	nbo.PutUint16(aliasAttr[2:], iflaIfAlias)
	copy(aliasAttr[4:], val)
	for len(aliasAttr)%4 != 0 {
		aliasAttr = append(aliasAttr, 0)
	}
	attrs = append(attrs, aliasAttr...)

	return rtnetlinkAck(unix.RTM_SETLINK, append(ifinfo, attrs...))
}

// rtnetlinkAck sends one acknowledged rtnetlink request and returns the
// kernel's error, nil on success.
func rtnetlinkAck(msgType int, body []byte) error {
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
	nbo.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
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
