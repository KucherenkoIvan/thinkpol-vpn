package lab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A subnet reservation covers the gap between choosing a lab's subnets and
// Docker having its networks: the allocation lock is held only to read
// what is used and record the choice, and the lab's containers start
// outside it. A reservation is a file in reservationsDir, created under the
// lock and locked by its owner's open file until the owner releases it
// (once docker compose up has returned, when the networks either exist on
// the daemon or never will), or dies. A file nobody locks has no owner and
// is reclaimed under the allocation lock: by the next allocation, or by
// labctl down.

const reservationSuffix = ".subnets"

func reservationsDir(lockDir string) string { return filepath.Join(lockDir, "reservations") }

// lockAllocation takes the host-wide subnet allocation lock. It is not the
// subnets.lock that labs before reservations held through their whole
// docker compose up: waiting behind those would undo the point. A subnet
// one of them takes at the same time is caught by Docker's overlap check
// and retried, as any other daemon user's is.
func lockAllocation(ctx context.Context, lockDir string) (func(), error) {
	return waitLock(ctx, "the subnet allocation lock", filepath.Join(lockDir, "subnet-reservations.lock"))
}

// reservation is a lab's subnets, reserved host-wide until release.
type reservation struct {
	subnets map[string]netSubnets
	file    *os.File
	// When the allocation lock was asked for, taken and given back.
	lockWait, lockFrom, lockTo time.Time
}

// release gives the subnets back. Whatever of them Docker has by now is
// used on the daemon, which every allocation reads.
func (r *reservation) release() {
	if r == nil || r.file == nil {
		return
	}
	_ = os.Remove(r.file.Name())
	_ = r.file.Close()
	r.file = nil
}

// reserveSubnets picks a subnet per network, avoiding every subnet used on
// the daemon (used) and every live reservation, and reserves them. It holds
// the host-wide allocation lock in lockDir only while it does.
func reserveSubnets(ctx context.Context, lockDir string, networks []Network, pool netip.Prefix, used func(context.Context) ([]netip.Prefix, error)) (*reservation, error) {
	r := &reservation{lockWait: time.Now()}
	unlock, err := lockAllocation(ctx, lockDir)
	if err != nil {
		return nil, err
	}
	r.lockFrom = time.Now()
	defer func() {
		unlock()
		r.lockTo = time.Now()
	}()
	dir := reservationsDir(lockDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	reserved, err := liveReservations(dir)
	if err != nil {
		return nil, err
	}
	onDaemon, err := used(ctx)
	if err != nil {
		return nil, err
	}
	if r.subnets, err = allocateSubnets(networks, pool, append(onDaemon, reserved...)); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "*"+reservationSuffix)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	var lines strings.Builder
	for _, s := range r.subnets {
		for _, p := range []netip.Prefix{s.v4, s.v6} {
			if p.IsValid() {
				lines.WriteString(p.String() + "\n")
			}
		}
	}
	ok, err := tryLockFile(f, true)
	if err == nil && !ok {
		err = errors.New("someone else holds it")
	}
	if err == nil {
		_, err = f.WriteString(lines.String())
	}
	if err != nil {
		_ = os.Remove(f.Name())
		_ = f.Close()
		return nil, fmt.Errorf("lab: subnet reservation %s: %w", f.Name(), err)
	}
	r.file = f
	return r, nil
}

// liveReservations reads the subnets of every reservation in dir whose
// owner holds it, and removes the others. The caller holds the allocation
// lock, which every reservation is created under.
func liveReservations(dir string) ([]netip.Prefix, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("lab: %w", err)
	}
	var out []netip.Prefix
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), reservationSuffix) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, free, err := tryLockMode(path, true)
		if err != nil {
			return nil, fmt.Errorf("lab: subnet reservation %s: %w", path, err)
		}
		if free {
			// Its owner released it or died.
			err := os.Remove(path)
			_ = f.Close()
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("lab: subnet reservation %s: %w", path, err)
			}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			// Released between the lock and the read.
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("lab: subnet reservation %s: %w", path, err)
		}
		for _, s := range strings.Fields(string(data)) {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("lab: subnet reservation %s: %q: %w", path, s, err)
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// reclaimReservations removes the reservations in lockDir whose owner is
// gone, under the allocation lock.
func reclaimReservations(ctx context.Context, lockDir string) error {
	unlock, err := lockAllocation(ctx, lockDir)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = liveReservations(reservationsDir(lockDir))
	return err
}
