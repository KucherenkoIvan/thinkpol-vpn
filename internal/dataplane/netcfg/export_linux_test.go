//go:build linux && !android

package netcfg

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// ClearFailingClose clears owner in the namespace at path with a real
// Close that fails: the ledger says link's MTU was changed from one the
// kernel refuses to set back.
func ClearFailingClose(path string, owner Owner, link string) error {
	return ClearWith(func() (Configurator, error) {
		c, err := NewInNamespace(path, owner)
		if err != nil {
			return nil, err
		}
		lc := c.(*linuxConfigurator)
		l, err := lc.h.LinkByName(link)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		lc.links.changed[link] = linkChange{index: l.Attrs().Index, origMTU: -1, mtu: l.Attrs().MTU}
		return c, nil
	}, nil)
}

// NewInNamespaceToKill is NewInNamespace, and a kill that puts /dev/null
// in place of the configurator's netlink socket: from then on every
// netlink request it makes fails, the first dump of a Close included.
func NewInNamespaceToKill(path string, owner Owner) (Configurator, func() error, error) {
	before, err := netlinkFDs()
	if err != nil {
		return nil, nil, err
	}
	c, err := NewInNamespace(path, owner)
	if err != nil {
		return nil, nil, err
	}
	after, err := netlinkFDs()
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	kill := func() error {
		null, err := unix.Open(os.DevNull, unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(null) }()
		for fd := range after {
			if !before[fd] {
				if err := unix.Dup3(null, fd, unix.O_CLOEXEC); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return c, kill, nil
}

// netlinkFDs are the process's open netlink sockets.
func netlinkFDs() (map[int]bool, error) {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool)
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if d, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN); err == nil && d == unix.AF_NETLINK {
			out[fd] = true
		}
	}
	return out, nil
}
