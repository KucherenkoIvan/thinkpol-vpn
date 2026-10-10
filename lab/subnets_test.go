package lab

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeNetworks answers `docker network ls -q` and `docker network inspect`
// like the CLI does, including failing the whole inspect when one network
// is missing.
type fakeNetworks struct {
	subnets    map[string]string
	notFound   string // the CLI's message for a missing network, %s = its id
	inspectErr error  // when set, inspect fails with it
	afterList  func()
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
				"noipam": "",
			},
			notFound: msg,
		}
		f.afterList = func() { delete(f.subnets, "gone") }
		used, err := usedSubnetsVia(t.Context(), f.docker)
		if err != nil {
			t.Fatalf("%q: %v", msg, err)
		}
		slices.SortFunc(used, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		want := []netip.Prefix{netip.MustParsePrefix("172.16.1.0/24"), netip.MustParsePrefix("fd00:1::/64")}
		if !slices.Equal(used, want) {
			t.Errorf("%q: used %v, want %v", msg, used, want)
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
