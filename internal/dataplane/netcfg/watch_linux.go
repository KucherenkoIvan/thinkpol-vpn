//go:build linux && !android

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// watchBuffer is the subscription's receive buffer: an Apply of tens of
// thousands of routes floods it, which is still only a change (ENOBUFS
// signals too).
const watchBuffer = 4 << 20

func (c *linuxConfigurator) Watch(ctx context.Context) (<-chan struct{}, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	sock, err := nl.SubscribeAt(c.ns, netns.None(), unix.NETLINK_ROUTE, unix.RTNLGRP_LINK,
		unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE)
	c.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("netcfg: watch routes: %w", err)
	}
	if err := sock.SetReceiveBufferSize(watchBuffer, false); err != nil {
		sock.Close()
		return nil, fmt.Errorf("netcfg: watch routes: %w", err)
	}
	out := make(chan struct{}, 1)
	signal := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	stop := context.AfterFunc(ctx, sock.Close)
	go func() {
		defer close(out)
		defer stop()
		defer sock.Close()
		for {
			msgs, _, err := sock.Receive()
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, unix.ENOBUFS) {
				signal() // events were lost: assume they mattered
				continue
			}
			if err != nil {
				return
			}
			for _, m := range msgs {
				if c.relevant(m) {
					signal()
				}
			}
		}
	}()
	return out, nil
}

// relevant reports whether an event may call for an Apply: a link that
// came, went or changed flags (a TUN going down takes its routes along
// without a word for IPv4), a main-table default route of no owner or an
// on-link route of the kernel's that changed, or our routes or rules
// deleted.
func (c *linuxConfigurator) relevant(m syscall.NetlinkMessage) bool {
	switch m.Header.Type {
	case unix.RTM_DELLINK:
		return true
	case unix.RTM_NEWLINK:
		// Wireless events and statistics come with no flag changed.
		return len(m.Data) >= unix.SizeofIfInfomsg && nl.DeserializeIfInfomsg(m.Data).Change != 0
	case unix.RTM_DELRULE:
		r, err := parseRawRule(m.Data)
		return err != nil || r.protocol == c.proto // unreadable: assume it mattered
	}
	if len(m.Data) < unix.SizeofRtMsg {
		return false
	}
	h := nl.DeserializeRtMsg(m.Data)
	switch m.Header.Type {
	case unix.RTM_DELROUTE:
		if h.Protocol == uint8(c.proto) {
			return true
		}
		fallthrough
	case unix.RTM_NEWROUTE:
		if h.Table != unix.RT_TABLE_MAIN || h.Type != unix.RTN_UNICAST {
			return false
		}
		return h.Protocol == unix.RTPROT_KERNEL ||
			h.Dst_len == 0 && !isOwnerProtocol(netlink.RouteProtocol(h.Protocol))
	}
	return false
}
