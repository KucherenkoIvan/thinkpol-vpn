//go:build linux && !android

package tun

import (
	"fmt"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread"
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
// /run/netns/<name>), from a process in another one. Reads, writes, Events
// and Close work from any thread: the device's file and netlink socket
// belong to that namespace. MTU doesn't: wireguard-go looks the interface
// up by name in the calling thread's namespace, so never call it on a
// device made here.
func CreateInNamespace(nsPath, name string, mtu int) (wgtun.Device, error) {
	var d wgtun.Device
	err := nsthread.Do(func() error {
		fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("tun: namespace %s: %w", nsPath, err)
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("tun: enter namespace %s: %w", nsPath, err)
		}
		d, err = Create(name, mtu)
		return err
	})
	if err != nil {
		if d != nil {
			_ = d.Close()
		}
		return nil, err
	}
	return d, nil
}
