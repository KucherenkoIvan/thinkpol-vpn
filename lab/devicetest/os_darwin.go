package main

import (
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// tcpdumpPath decodes captures as a judge will (`tcpdump -n -A -r`).
const tcpdumpPath = "/usr/sbin/tcpdump"

// physicalInterface is the interface of the IPv4 default route, asked of
// the kernel (netcfg's lookup, as `route -n get default`).
func physicalInterface() (string, error) {
	name, _, err := netcfg.DefaultInterface(netcfg.IPv4)
	return name, err
}
