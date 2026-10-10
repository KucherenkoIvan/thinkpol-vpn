package lab

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"strings"
)

// SubnetPoolEnv overrides the IPv4 range lab networks get their /24s from.
const SubnetPoolEnv = "THINKPOL_LAB_SUBNET_POOL"

// defaultSubnetPool sits just below Docker's default address pools (which
// start at 172.17.0.0/16), so labs don't use up the pools other projects on
// the daemon allocate from: 256 lab networks in all.
const defaultSubnetPool = "172.16.0.0/16"

// netSubnets are one lab network's subnets; v6 is invalid on an IPv4Only
// network.
type netSubnets struct {
	v4, v6 netip.Prefix
}

func subnetPool() (netip.Prefix, error) {
	s := os.Getenv(SubnetPoolEnv)
	if s == "" {
		s = defaultSubnetPool
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 24 || p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("lab: %s=%q: want an IPv4 prefix between /8 and /24", SubnetPoolEnv, s)
	}
	return p, nil
}

// usedSubnets lists the subnets of every network on the daemon, the lab's
// and everyone else's.
func usedSubnets(ctx context.Context) ([]netip.Prefix, error) {
	res, err := docker(ctx, "network", "ls", "-q")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(res.Stdout)
	if len(ids) == 0 {
		return nil, nil
	}
	res, err = docker(ctx, append([]string{"network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"}, ids...)...)
	if err != nil {
		return nil, err
	}
	var used []netip.Prefix
	for _, s := range strings.Fields(res.Stdout) {
		if p, err := netip.ParsePrefix(s); err == nil {
			used = append(used, p.Masked())
		}
	}
	return used, nil
}

// allocateSubnets picks, for each network, a free /24 from pool and a /64
// from a fresh random unique-local /48, avoiding used.
func allocateSubnets(networks []Network, pool netip.Prefix, used []netip.Prefix) (map[string]netSubnets, error) {
	free := func(p netip.Prefix) bool {
		for _, u := range used {
			if u.Overlaps(p) {
				return false
			}
		}
		return true
	}
	var candidates []netip.Prefix
	base := pool.Addr().As4()
	for i := range 1 << (24 - pool.Bits()) {
		a := base
		a[1] += byte(i >> 8)
		a[2] += byte(i)
		candidates = append(candidates, netip.PrefixFrom(netip.AddrFrom4(a), 24))
	}
	mrand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })

	var ula [16]byte
	ula[0] = 0xfd
	if _, err := rand.Read(ula[1:6]); err != nil {
		return nil, err
	}
	out := map[string]netSubnets{}
	for i, n := range networks {
		var s netSubnets
		for len(candidates) > 0 && !s.v4.IsValid() {
			if c := candidates[0]; free(c) {
				s.v4 = c
				used = append(used, c)
			}
			candidates = candidates[1:]
		}
		if !s.v4.IsValid() {
			return nil, errors.New("lab: no free /24 left in " + pool.String() + "; make lab-down in idle checkouts, or set " + SubnetPoolEnv)
		}
		if !n.IPv4Only {
			a := ula
			a[6], a[7] = byte(i>>8), byte(i)
			s.v6 = netip.PrefixFrom(netip.AddrFrom16(a), 64)
			if !free(s.v6) {
				return nil, errors.New("lab: random IPv6 subnet " + s.v6.String() + " is taken")
			}
		}
		out[n.Name] = s
	}
	return out, nil
}

// isOverlap recognizes Docker refusing a subnet another network took first.
func isOverlap(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "overlap")
}
