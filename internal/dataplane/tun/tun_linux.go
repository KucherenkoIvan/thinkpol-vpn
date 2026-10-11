//go:build linux && !android

package tun

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Create creates a TUN named name with an MTU of mtu in the calling
// thread's network namespace. Closing it removes the interface.
func Create(name string, mtu int) (wgtun.Device, error) {
	d, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun: create %s: %w", name, err)
	}
	return d, nil
}

// CreateInNamespace is Create inside the network namespace at nsPath (e.g.
// /run/netns/<name>), from a process in another one. The device keeps
// working from any thread: its file and its netlink socket belong to that
// namespace.
func CreateInNamespace(nsPath, name string, mtu int) (wgtun.Device, error) {
	type result struct {
		d   wgtun.Device
		err error
	}
	done := make(chan result, 1)
	go func() {
		// Never unlocked: the thread leaves with this goroutine, so no
		// other goroutine ever runs in the other namespace.
		runtime.LockOSThread()
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- result{err: fmt.Errorf("tun: namespace %s: %w", nsPath, err)}
			return
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		_ = unix.Close(fd)
		if err != nil {
			done <- result{err: fmt.Errorf("tun: enter namespace %s: %w", nsPath, err)}
			return
		}
		d, err := Create(name, mtu)
		done <- result{d, err}
	}()
	r := <-done
	return r.d, r.err
}
