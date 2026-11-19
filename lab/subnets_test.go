package lab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeNetworks answers `docker network ls -q` and `docker network inspect`
// like the CLI does, including failing the whole inspect when one network
// is missing.
type fakeNetworks struct {
	subnets    map[string]string
	notFound   string // the CLI's message for a missing network, %s = its id
	inspectErr error  // when set, inspect fails with it
	alsoStderr string // another error line beside the missing networks'
	afterList  func()
	mu         sync.Mutex
	inspects   int
}

func (f *fakeNetworks) docker(_ context.Context, args ...string) (Result, error) {
	switch {
	case slices.Equal(args, []string{"network", "ls", "-q", "--no-trunc"}):
		var ids []string
		for id := range f.subnets {
			ids = append(ids, id)
		}
		if f.afterList != nil {
			f.afterList()
		}
		return Result{Stdout: strings.Join(ids, "\n") + "\n"}, nil
	case len(args) > 4 && args[0] == "network" && args[1] == "inspect":
		f.mu.Lock()
		f.inspects++
		f.mu.Unlock()
		if f.inspectErr != nil {
			return Result{Stderr: f.inspectErr.Error(), ExitCode: 1}, f.inspectErr
		}
		var res Result
		for _, id := range args[4:] {
			if s, ok := f.subnets[id]; ok {
				res.Stdout += s + " \n"
			} else {
				res.Stderr += fmt.Sprintf(f.notFound, id) + "\n"
			}
		}
		if res.Stderr != "" && f.alsoStderr != "" {
			res.Stderr += f.alsoStderr + "\n"
		}
		if res.Stderr != "" {
			res.ExitCode = 1
			return res, errors.New("docker network inspect: exit 1: " + strings.TrimSpace(res.Stderr))
		}
		return res, nil
	}
	return Result{}, fmt.Errorf("unexpected docker %v", args)
}

func TestUsedSubnetsSkipsNetworksRemovedAfterTheList(t *testing.T) {
	for _, msg := range []string{
		"Error response from daemon: network %s not found",
		"Error: No such network: %s",
	} {
		f := &fakeNetworks{
			subnets: map[string]string{
				"kept":   "172.16.1.0/24 fd00:1::/64",
				"gone":   "172.16.2.0/24",
				"gone2":  "172.16.3.0/24",
				"noipam": "",
			},
			notFound: msg,
		}
		f.afterList = func() { delete(f.subnets, "gone"); delete(f.subnets, "gone2") }
		used, err := usedSubnetsVia(t.Context(), f.docker)
		if err != nil {
			t.Fatalf("%q: %v", msg, err)
		}
		slices.SortFunc(used, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		want := []netip.Prefix{netip.MustParsePrefix("172.16.1.0/24"), netip.MustParsePrefix("fd00:1::/64")}
		if !slices.Equal(used, want) {
			t.Errorf("%q: used %v, want %v", msg, used, want)
		}
		// The CLI printed the networks it found: no inspect one by one
		// (four networks are one chunk).
		if f.inspects != 1 {
			t.Errorf("%q: %d inspects, want 1 however many networks vanished", msg, f.inspects)
		}
		// The freed /24 is allocatable again.
		pool := netip.MustParsePrefix("172.16.0.0/22")
		got, err := allocateSubnets([]Network{{Name: "a", IPv4Only: true}, {Name: "b", IPv4Only: true}, {Name: "c", IPv4Only: true}}, pool, used)
		if err != nil {
			t.Fatalf("%q: allocate: %v", msg, err)
		}
		for name, s := range got {
			if s.v4 == want[0] {
				t.Errorf("%q: network %s got the used %v", msg, name, s.v4)
			}
		}
	}
}

// Networks are inspected in chunks at once: every chunk's subnets count,
// with networks gone from several of them.
func TestUsedSubnetsReadsEveryChunk(t *testing.T) {
	f := &fakeNetworks{subnets: map[string]string{}, notFound: "Error response from daemon: network %s not found"}
	var want []netip.Prefix
	for i := range 3*inspectChunk + 1 {
		id := fmt.Sprintf("net%02d", i)
		f.subnets[id] = fmt.Sprintf("172.16.%d.0/24", i)
		if i%inspectChunk != 1 {
			want = append(want, netip.MustParsePrefix(f.subnets[id]))
		}
	}
	f.afterList = func() {
		for id := range f.subnets {
			var i int
			_, _ = fmt.Sscanf(id, "net%d", &i)
			if i%inspectChunk == 1 {
				delete(f.subnets, id)
			}
		}
	}
	used, err := usedSubnetsVia(t.Context(), f.docker)
	if err != nil {
		t.Fatal(err)
	}
	sortPrefixes := func(ps []netip.Prefix) {
		slices.SortFunc(ps, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	}
	sortPrefixes(used)
	sortPrefixes(want)
	if !slices.Equal(used, want) {
		t.Errorf("used %v, want %v", used, want)
	}
}

func TestUsedSubnetsFailsClosed(t *testing.T) {
	for name, f := range map[string]*fakeNetworks{
		// A daemon going away mid-read must not read as "no subnets used".
		"daemon gone": {
			subnets:    map[string]string{"a": "172.16.1.0/24"},
			inspectErr: errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"),
		},
		"socket gone": {
			subnets:    map[string]string{"a": "172.16.1.0/24"},
			inspectErr: errors.New("error during connect: Get \"http://docker/v1.47/networks/a\": dial unix /var/run/docker.sock: connect: no such file or directory"),
		},
		"cli gone": {
			subnets:    map[string]string{"a": "172.16.1.0/24"},
			inspectErr: errors.New("sh: docker: command not found"),
		},
		"permission": {
			subnets:    map[string]string{"a": "172.16.1.0/24"},
			inspectErr: errors.New("permission denied while trying to connect to the Docker daemon socket"),
		},
		"garbage subnet": {
			subnets: map[string]string{"a": "172.16.1.0/24", "b": "<no value>"},
		},
	} {
		if used, err := usedSubnetsVia(t.Context(), f.docker); err == nil {
			t.Errorf("%s: no error, used %v", name, used)
		}
	}

	// A network gone and something else wrong in the same inspect: the
	// output may be short of more than the missing network.
	for _, also := range []string{
		"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
		"Error response from daemon: network 0000 not found",
	} {
		f := &fakeNetworks{subnets: map[string]string{"a": "172.16.1.0/24", "b": "172.16.2.0/24"}, notFound: "Error response from daemon: network %s not found", alsoStderr: also}
		f.afterList = func() { delete(f.subnets, "b") }
		if used, err := usedSubnetsVia(t.Context(), f.docker); err == nil {
			t.Errorf("a network gone and %q: no error, used %v", also, used)
		}
	}

	// Every listed network vanishing at once is not believable: the daemon's
	// own networks always exist.
	f := &fakeNetworks{subnets: map[string]string{"a": "172.16.1.0/24", "b": "172.16.2.0/24"}, notFound: "Error response from daemon: network %s not found"}
	f.afterList = func() { clear(f.subnets) }
	if used, err := usedSubnetsVia(t.Context(), f.docker); err == nil {
		t.Errorf("every network gone: no error, used %v", used)
	}
}

func TestNetworkNotFound(t *testing.T) {
	const id = "3486a0cbe058aa"
	fail := errors.New("exit 1")
	for _, c := range []struct {
		stderr string
		exit   int
		err    error
		want   bool
	}{
		{"Error response from daemon: network 3486a0cbe058aa not found", 1, fail, true},
		{"Error: No such network: 3486a0cbe058aa", 1, fail, true},
		{"Error: No such object: 3486a0cbe058aa\n", 1, fail, true},
		// Another network missing, or one whose id merely starts with id.
		{"Error response from daemon: network 0000 not found", 1, fail, false},
		{"Error: No such network: 3486a0cbe058aabb", 1, fail, false},
		{"error during connect: dial unix /var/run/docker.sock: connect: no such file or directory", 1, fail, false},
		{"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", 1, fail, false},
		{"sh: docker: command not found", 127, fail, false},
		{"permission denied", 1, fail, false},
		// The docker binary itself missing: no exit, no stderr.
		{"", 0, errors.New(`exec: "docker": executable file not found in $PATH`), false},
		{"Error response from daemon: network 3486a0cbe058aa not found", 0, nil, false},
	} {
		if got := networkNotFound(Result{Stderr: c.stderr, ExitCode: c.exit}, c.err, id); got != c.want {
			t.Errorf("networkNotFound(%q) = %v", c.stderr, got)
		}
	}
}

func TestSubnetPoolRefusesTheDeadEndNameserver(t *testing.T) {
	deadEnd := netip.MustParseAddr(DeadEndNameserver)
	for _, bits := range []int{24, 16, 8} {
		pool := netip.PrefixFrom(deadEnd, bits).Masked()
		t.Setenv(SubnetPoolEnv, pool.String())
		if p, err := subnetPool(); err == nil {
			t.Errorf("%s=%s: got pool %v, want it refused: it contains %s", SubnetPoolEnv, pool, p, deadEnd)
		}
	}
	next := deadEnd.As4()
	next[2], next[3] = next[2]+1, 0
	beside := netip.PrefixFrom(netip.AddrFrom4(next), 24)
	t.Setenv(SubnetPoolEnv, beside.String())
	if _, err := subnetPool(); err != nil {
		t.Errorf("%s=%s, beside the dead-end nameserver: %v", SubnetPoolEnv, beside, err)
	}
}

// Files that could reach the lab (Go code, YAML, testdata, scripts; not
// macOS or Windows files) may not use the dead-end nameserver's address,
// or a prefix of /8 or longer (what a lab network or a test's address
// could be) that contains it: a node that reached it would turn the dead
// end into a resolver.
// Shorter prefixes are routes such as 0.0.0.0/0, not addresses.
func TestOnlyTheNodesUseTheDeadEndNameserver(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	deadEnd := netip.MustParseAddr(DeadEndNameserver)
	literal := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?\b`)
	definition := filepath.Join(root, "lab", "compose.go")
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || path == binRoot(root)) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !scannedForTheDeadEnd(path) || strings.Contains(name, "_darwin") || strings.Contains(name, "_windows") || strings.Contains(name, "_ios") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if path == definition {
				if l := strings.TrimSpace(line); strings.HasPrefix(l, "//") || strings.HasPrefix(l, "const DeadEndNameserver ") {
					continue
				}
			}
			for _, lit := range literal.FindAllString(line, -1) {
				if rel, _ := filepath.Rel(root, path); usesAddr(lit, deadEnd) {
					t.Errorf("%s:%d: %s reaches the dead-end nameserver %s", rel, i+1, lit, deadEnd)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// scannedForTheDeadEnd reports whether path is a file whose addresses can
// reach a lab node: Go code, the maps and other YAML, testdata, scripts
// and the images' files. Docs, which name the address, are left out.
func scannedForTheDeadEnd(path string) bool {
	if slices.Contains(strings.Split(filepath.ToSlash(path), "/"), "testdata") {
		return true
	}
	switch filepath.Ext(path) {
	case ".go", ".yaml", ".yml", ".json", ".sh", ".py", ".conf":
		return true
	}
	return strings.HasPrefix(filepath.Base(path), "Dockerfile")
}

func usesAddr(literal string, a netip.Addr) bool {
	if p, err := netip.ParsePrefix(literal); err == nil {
		return p.Bits() >= 8 && p.Contains(a)
	}
	addr, err := netip.ParseAddr(literal)
	return err == nil && addr == a
}

// Lab starts that ask while a read of the daemon's subnets runs take its
// answer; one that must not miss what happened before it asked (a try after
// an overlap) gets a read of its own, and so does one asking after the read
// ended.
func TestSharedReadJoinsARunningRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reads := 0
		release := make(chan struct{})
		s := &sharedRead{bound: time.Minute, read: func(ctx context.Context) ([]netip.Prefix, error) {
			reads++
			n := reads
			if n == 1 {
				<-release
			}
			return []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, byte(n), 0}), 24)}, nil
		}}
		ask := func(notBefore time.Time) chan []netip.Prefix {
			ch := make(chan []netip.Prefix, 1)
			go func() {
				used, err := s.get(t.Context(), notBefore)
				if err != nil {
					t.Error(err)
				}
				ch <- used
			}()
			synctest.Wait() // it has asked, and waits for its answer or has it
			return ch
		}
		check := func(name string, ch chan []netip.Prefix, want string) {
			t.Helper()
			used := <-ch
			if len(used) != 1 || used[0].String() != want {
				t.Errorf("%s: got %v, want %s", name, used, want)
			}
		}
		first := ask(time.Time{})
		joined := ask(time.Time{})
		time.Sleep(time.Second) // the bubble's clock: asks after the running read began
		check("one that must not miss what came before it", ask(time.Now()), "172.16.2.0/24")
		close(release)
		check("the first", first, "172.16.1.0/24")
		check("one asking while it ran", joined, "172.16.1.0/24")
		check("one asking after it ended", ask(time.Time{}), "172.16.3.0/24")
	})
}

// One read's inspects in flight are capped, however many networks the
// daemon has: a run's labs read together.
func TestUsedSubnetsCapsInspectsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const chunks = 4 * inspectsAtOnce
		var mu sync.Mutex
		inFlight, most, inspects := 0, 0, 0
		var ids []string
		for i := range chunks * inspectChunk {
			ids = append(ids, fmt.Sprintf("net%03d", i))
		}
		run := func(_ context.Context, args ...string) (Result, error) {
			if args[1] == "ls" {
				return Result{Stdout: strings.Join(ids, "\n")}, nil
			}
			mu.Lock()
			inFlight++
			inspects++
			most = max(most, inFlight)
			mu.Unlock()
			time.Sleep(time.Second) // the bubble's clock: every inspect not blocked is in flight
			mu.Lock()
			inFlight--
			mu.Unlock()
			return Result{Stdout: "172.16.1.0/24 "}, nil
		}
		if _, err := usedSubnetsVia(t.Context(), run); err != nil {
			t.Fatal(err)
		}
		if inspects != chunks || most != inspectsAtOnce {
			t.Errorf("%d inspects, at most %d at once; want %d, %d at once", inspects, most, chunks, inspectsAtOnce)
		}
	})
}

// A try after an overlap, and a first try that finds the pool full, read
// the daemon afresh: the read before the slot is as old as the slot wait.
func TestCreateTriesReadAfresh(t *testing.T) {
	a, b := netip.MustParsePrefix("172.16.0.0/24"), netip.MustParsePrefix("172.16.1.0/24")
	pool := netip.MustParsePrefix("172.16.0.0/23")
	for name, tc := range map[string]struct {
		stale, daemon []netip.Prefix // the read before the slot; the daemon now
		wantUps       int
	}{
		// a was free when read, and someone took it since: the first try's
		// up overlaps; b, used then, is free now.
		"overlap": {stale: []netip.Prefix{b}, daemon: []netip.Prefix{a}, wantUps: 2},
		// Both were used when read; b is free now.
		"pool full": {stale: []netip.Prefix{a, b}, daemon: []netip.Prefix{a}, wantUps: 1},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			nets := []Network{{Name: "n", IPv4Only: true}}
			var (
				r          *reservation
				reads, ups int
				overlapAt  time.Time
				notBefores []time.Time
			)
			defer func() { r.release() }()
			read := func(_ context.Context, notBefore time.Time) ([]netip.Prefix, error) {
				reads++
				notBefores = append(notBefores, notBefore)
				return tc.daemon, nil
			}
			reserve := func(ctx context.Context, used func(context.Context) ([]netip.Prefix, error)) (err error) {
				r.release()
				r, err = reserveSubnets(ctx, dir, nets, pool, used)
				return err
			}
			up := func(_ context.Context, attempt int) error {
				ups++
				if slices.Contains(tc.daemon, r.subnets["n"].v4) {
					overlapAt = time.Now()
					return errors.New("Error response from daemon: Pool overlaps with other one on this address space")
				}
				return nil
			}
			start := time.Now()
			if err := createTries(t.Context(), tc.stale, read, reserve, up, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("%v (%d ups, %d reads)", err, ups, reads)
			}
			if got := r.subnets["n"].v4; got != b {
				t.Errorf("got %v, want %v", got, b)
			}
			if ups != tc.wantUps || reads != 1 {
				t.Errorf("%d ups, %d reads; want %d, 1", ups, reads, tc.wantUps)
			}
			after := start
			if !overlapAt.IsZero() {
				after = overlapAt
			}
			if len(notBefores) == 1 && notBefores[0].Before(after) {
				t.Errorf("the fresh read may have begun at %v, before %v", notBefores[0], after)
			}
		})
	}
}

func TestParseGateways(t *testing.T) {
	const p = "tplab-x-1"
	got, err := parseGateways(p, p+"_wan 172.16.4.1 fd12:3456::1 \n\n"+p+"_lan 172.16.5.1/24 \n"+p+"_bare \n")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]netip.Addr{
		"wan": {netip.MustParseAddr("172.16.4.1"), netip.MustParseAddr("fd12:3456::1")},
		"lan": {netip.MustParseAddr("172.16.5.1")},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if _, err := parseGateways(p, "tplab-y-1_wan 172.16.4.1\n"); err == nil {
		t.Error("another lab's network: no error")
	}
}
