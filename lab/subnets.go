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
	"sync"
	"time"
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
	if p.Contains(netip.MustParseAddr(DeadEndNameserver)) {
		return netip.Prefix{}, fmt.Errorf("lab: %s=%q contains the nodes' dead-end nameserver %s, which no lab network may reach", SubnetPoolEnv, s, DeadEndNameserver)
	}
	return p, nil
}

// usedSubnets lists the subnets of every network on the daemon, the lab's
// and everyone else's.
func usedSubnets(ctx context.Context) ([]netip.Prefix, error) {
	return usedSubnetsVia(ctx, docker)
}

// daemonSubnets is usedSubnets shared by the lab starts of this process:
// a run starts as many labs at once as it has slots, and each read asks
// the daemon about every network on it, behind whatever networks the
// daemon is creating or removing.
var daemonSubnets = &sharedRead{read: usedSubnets, bound: 5 * time.Minute}

// sharedRead runs read for whoever asks, and has a caller that asks while
// a read is running take that one's answer. A read that began before the
// caller asked can miss a network created just before: as a read and the
// docker compose up after it can anyway, whose overlap means another try
// (Lab.create), which then asks for a read that began after it asks.
type sharedRead struct {
	read  func(context.Context) ([]netip.Prefix, error)
	bound time.Duration // a read's own, as it outlives the caller that began it

	mu  sync.Mutex
	cur *subnetRead
}

type subnetRead struct {
	began time.Time
	done  chan struct{}
	used  []netip.Prefix
	err   error
}

// get is a read's answer: the running one's, if it began at notBefore or
// later, else a new one's.
func (s *sharedRead) get(ctx context.Context, notBefore time.Time) ([]netip.Prefix, error) {
	s.mu.Lock()
	r := s.cur
	if r == nil || r.began.Before(notBefore) {
		r = &subnetRead{began: time.Now(), done: make(chan struct{})}
		s.cur = r
		go func() {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.bound)
			defer cancel()
			r.used, r.err = s.read(rctx)
			s.mu.Lock()
			if s.cur == r {
				s.cur = nil
			}
			s.mu.Unlock()
			close(r.done)
		}()
	}
	s.mu.Unlock()
	select {
	case <-r.done:
		return slices.Clone(r.used), r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dockerFunc runs a docker CLI command, as docker does.
type dockerFunc func(ctx context.Context, args ...string) (Result, error)

// inspectChunk is how many networks one docker network inspect asks
// about; usedSubnetsVia runs the chunks at once. The CLI asks the daemon
// one network after another, and under load each request waits behind
// whatever network the daemon is creating or removing at the time.
const inspectChunk = 4

// inspectsAtOnce caps one read's inspects in flight: a run's labs read
// together, each read starting a docker CLI per chunk, on a daemon whose
// disk is already what every lab waits on.
const inspectsAtOnce = 8

// usedSubnetsVia is usedSubnets through run. Other daemon users remove
// networks at any time, also between the list and the inspect: a network
// that is gone by then no longer holds a subnet and is skipped. The CLI
// still prints every network it found, so an inspect whose every error is
// a listed network not found is the answer for the rest. Anything else
// that goes wrong fails, so a sick daemon never reads as "nothing used".
func usedSubnetsVia(ctx context.Context, run dockerFunc) ([]netip.Prefix, error) {
	res, err := run(ctx, "network", "ls", "-q", "--no-trunc")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(res.Stdout)
	if len(ids) == 0 {
		return nil, nil
	}
	chunks := slices.Collect(slices.Chunk(ids, inspectChunk))
	outs := make([]string, len(chunks))
	gone := make([]int, len(chunks))
	errs := make([]error, len(chunks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, inspectsAtOnce)
	for i, chunk := range chunks {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := run(ctx, append([]string{"network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"}, chunk...)...)
			if err != nil {
				n, ok := networksNotFound(res, err, chunk)
				if !ok {
					errs[i] = err
					return
				}
				gone[i] = n
			}
			outs[i] = res.Stdout
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	total := 0
	for _, n := range gone {
		total += n
	}
	if total == len(ids) {
		return nil, fmt.Errorf("lab: none of the %d networks docker listed could be inspected", len(ids))
	}
	res = Result{Stdout: strings.Join(outs, " ")}
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

// networksNotFound counts the networks of ids a failed inspect says it
// didn't find; ok only when that is all its stderr says.
func networksNotFound(res Result, err error, ids []string) (gone int, ok bool) {
	for _, line := range strings.Split(res.Stderr, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		line := Result{Stderr: line, ExitCode: res.ExitCode}
		if !slices.ContainsFunc(ids, func(id string) bool { return networkNotFound(line, err, id) }) {
			return 0, false
		}
		gone++
	}
	return gone, gone > 0
}

func isIDChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c == '-' || c == '_' || c == '.'
}

// errNoFreeSubnet is the pool, as allocateSubnets saw it, being full.
var errNoFreeSubnet = errors.New("lab: no free /24 left")

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
			return nil, fmt.Errorf("%w in %s; make lab-down in idle checkouts, or set %s", errNoFreeSubnet, pool, SubnetPoolEnv)
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
