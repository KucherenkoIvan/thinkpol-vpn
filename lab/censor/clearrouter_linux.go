//go:build linux

package censor

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ClearRouter clears what a censor leaves in the router after it stops,
// so the next censor starts from the state a fresh router has: the
// censor's table (its queue rule), left behind by an unclean stop, and
// every conntrack entry of the router's network namespace, IPv4 and IPv6.
// The queue rule's ct match keeps conntrack on, so the flows a censor saw
// outlive it, their TCP state and timeouts with them.
func ClearRouter() error {
	removeQueueRule()
	return flushConntrack()
}

// ctnetlink's flush: IPCTNL_MSG_CT_DELETE with no tuple deletes every entry
// of the message's family.
const (
	nfnlSubsysCTNetlink = 1
	ipctnlMsgCTDelete   = 2
)

func flushConntrack() error {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return fmt.Errorf("censor: conntrack: %w", err)
	}
	defer func() { _ = c.Close() }()
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		// struct nfgenmsg: family, version (NFNETLINK_V0), resource id.
		_, err := c.Execute(netlink.Message{
			Header: netlink.Header{
				Type:  netlink.HeaderType(nfnlSubsysCTNetlink<<8 | ipctnlMsgCTDelete),
				Flags: netlink.Request | netlink.Acknowledge,
			},
			Data: []byte{family, 0, 0, 0},
		})
		if err != nil {
			return fmt.Errorf("censor: conntrack flush (family %d): %w", family, err)
		}
	}
	return nil
}
