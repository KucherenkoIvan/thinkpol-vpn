package netcfg

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// Inspect reads the owners' routes from the routing table: those carrying
// routeFlag that their owner's record names, as the kernel holds them,
// and apart the ones carrying it that no record names (another program's,
// or an agent's it didn't record). macOS has no policy rules, so that
// list is always empty. It opens LockDir without making it, and takes no
// lock.
func Inspect() Inspection {
	k, err := openKernel()
	if err != nil {
		return Inspection{RoutesUnreadable: err.Error()}
	}
	defer func() { _ = k.close() }()
	return inspectDarwin(k, LockDir)
}

func inspectDarwin(k kernel, dirPath string) Inspection {
	recs, err := readRecords(dirPath)
	if err != nil {
		return Inspection{RoutesUnreadable: err.Error()}
	}
	rs, err := k.routes()
	if err != nil {
		return Inspection{RoutesUnreadable: fmt.Sprintf("netcfg: list routes: %v", err)}
	}
	ifcs, err := k.interfaces()
	if err != nil {
		return Inspection{RoutesUnreadable: fmt.Sprintf("netcfg: list interfaces: %v", err)}
	}
	names := make(map[int]string, len(ifcs))
	for _, i := range ifcs {
		names[i.index] = i.name
	}
	var out Inspection
	for _, r := range rs {
		if r.ignored() || !r.dst.IsValid() || r.flags&routeFlag == 0 {
			continue
		}
		recorded := false
		for _, o := range Owners {
			if recs[o][r.key()] {
				out.Routes = append(out.Routes, darwinHostRoute(o, r, names))
				recorded = true
			}
		}
		if !recorded {
			out.UnrecordedProto2 = append(out.UnrecordedProto2, darwinHostRoute(0, r, names))
		}
	}
	for _, rs := range [][]HostRoute{out.Routes, out.UnrecordedProto2} {
		slices.SortFunc(rs, func(a, b HostRoute) int {
			if c := comparePrefixes(a.Dst, b.Dst); c != 0 {
				return c
			}
			return int(a.Owner) - int(b.Owner)
		})
	}
	return out
}

// readRecords reads every owner's record in dirPath; a directory that
// isn't there holds none.
func readRecords(dirPath string) (map[Owner]map[rkey]bool, error) {
	out := map[Owner]map[rkey]bool{}
	boot, err := trusteddir.BootSession()
	if err != nil {
		return nil, fmt.Errorf("netcfg: %w", err)
	}
	d, err := trusteddir.Open(dirPath)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("netcfg: %w", err)
	}
	defer func() { _ = d.Close() }()
	for _, o := range Owners {
		rec, err := readRecord(d, recordName(o), boot)
		if err != nil {
			return nil, fmt.Errorf("netcfg: reading %v's route record: %w", o, err)
		}
		out[o] = rec
	}
	return out, nil
}

func darwinHostRoute(o Owner, r kroute, names map[int]string) HostRoute {
	hr := HostRoute{Owner: o, Family: FamilyOf(r.dst.Addr()), Dst: r.dst, Type: "unicast"}
	switch {
	case r.flags&unix.RTF_REJECT != 0:
		hr.Type = "unreachable"
	case r.flags&unix.RTF_BLACKHOLE != 0:
		hr.Type = "blackhole"
	}
	if r.flags&unix.RTF_GATEWAY != 0 && r.gw.IsValid() {
		hr.Gateway = r.gw
	}
	idx := r.index
	if !hr.Gateway.IsValid() && r.link != 0 {
		idx = r.link
	}
	hr.Interface = names[idx]
	if r.flags&unix.RTF_IFSCOPE != 0 {
		hr.Scope = names[r.index]
	}
	return hr
}
