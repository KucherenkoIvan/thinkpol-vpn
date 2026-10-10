package lab

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"slices"
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
	return usedSubnetsVia(ctx, docker)
}

// dockerFunc runs a docker CLI command, as docker does.
type dockerFunc func(ctx context.Context, args ...string) (Result, error)

// usedSubnetsVia is usedSubnets through run. Other daemon users remove
// networks at any time, also between the list and the inspect: a network
// that is gone by then no longer holds a subnet and is skipped. Anything
// else that goes wrong fails, so a sick daemon never reads as "nothing used".
func usedSubnetsVia(ctx context.Context, run dockerFunc) ([]netip.Prefix, error) {
	res, err := run(ctx, "network", "ls", "-q", "--no-trunc")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(res.Stdout)
	if len(ids) == 0 {
		return nil, nil
	}
	inspect := func(ids ...string) (Result, error) {
		return run(ctx, append([]string{"network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"}, ids...)...)
	}
	res, err = inspect(ids...)
	if err != nil && slices.ContainsFunc(ids, func(id string) bool { return networkNotFound(res, err, id) }) {
		// Some network vanished; which one, only inspecting them one by one
		// tells.
		var out strings.Builder
		read := 0
		for _, id := range ids {
			res, err := inspect(id)
			if networkNotFound(res, err, id) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out.WriteString(res.Stdout + " ")
			read++
		}
		if read == 0 {
			return nil, fmt.Errorf("lab: none of the %d networks docker listed could be inspected", len(ids))
		}
		res, err = Result{Stdout: out.String()}, nil
	}
	if err != nil {
		return nil, err
	}
	var used []netip.Prefix
	for _, s := range strings.Fields(res.Stdout) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("lab: docker network subnet %q: %w", s, err)
		}
		used = append(used, p.Masked())
	}
	return used, nil
}

// networkNotFound recognizes the docker CLI failing because the network id
// doesn't exist (any more): "Error response from daemon: network <id> not
// found" from the daemon, "No such network: <id>" or "No such object: <id>"
// from other client versions. Only a message naming id counts.
func networkNotFound(res Result, err error, id string) bool {
	if err == nil || res.ExitCode == 0 || id == "" {
		return false
	}
	msg := strings.ToLower(res.Stderr)
	id = strings.ToLower(id)
	for _, want := range []string{"network " + id + " not found", "no such network: " + id, "no such object: " + id} {
		if i := strings.Index(msg, want); i >= 0 {
			if end := i + len(want); end == len(msg) || !isIDChar(msg[end]) {
				return true
			}
		}
	}
	return false
}

func isIDChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c == '-' || c == '_' || c == '.'
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
