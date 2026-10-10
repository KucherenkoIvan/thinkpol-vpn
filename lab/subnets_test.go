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
	case slices.Equal(args, []string{"network", "ls", "-q"}):
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

func TestUsedSubnetsFailsOnOtherInspectErrors(t *testing.T) {
	f := &fakeNetworks{
		subnets:    map[string]string{"a": "172.16.1.0/24"},
		inspectErr: errors.New("permission denied while trying to connect to the Docker daemon socket"),
	}
	if _, err := usedSubnetsVia(t.Context(), f.docker); err == nil {
		t.Fatal("an inspect failure other than not found was ignored")
	}
}

func TestIsNotFound(t *testing.T) {
	fail := errors.New("exit 1")
	for _, c := range []struct {
		res  Result
		err  error
		want bool
	}{
		{Result{Stderr: "Error response from daemon: network abc not found", ExitCode: 1}, fail, true},
		{Result{Stderr: "Error: No such network: abc", ExitCode: 1}, fail, true},
		{Result{Stderr: "Error: No such object: abc", ExitCode: 1}, fail, true},
		{Result{Stderr: "permission denied", ExitCode: 1}, fail, false},
		// The docker binary itself missing is not a missing network.
		{Result{}, errors.New(`docker network inspect: exec: "docker": executable file not found in $PATH`), false},
		{Result{Stderr: "network abc not found"}, nil, false},
	} {
		if got := isNotFound(c.res, c.err); got != c.want {
			t.Errorf("isNotFound(%q, %v) = %v", c.res.Stderr, c.err, got)
		}
	}
}
