package main

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
)

// wrap is err as a command returns it, with context.
func wrap(err error) error { return fmt.Errorf("context: %w", err) }

// What a command fails with maps to one code, however it is wrapped:
// typed errors first, then the local API's refusals by code, and 1 for
// anything unnamed, an errno alone included.
func TestExitCodeMapsEachFailure(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{nil, exitOK},
		{errors.New("anything else"), exitFailure},
		{wrap(errUsage), exitUsage},
		{argsError{errors.New("a removed form")}, exitUsage},
		{wrap(localapi.ErrUnknownPreset), exitUsage},
		{wrap(inputError{wrap(fs.ErrNotExist)}), exitNoInput},
		{wrap(inputError{wrap(fs.ErrPermission)}), exitNoPerm},
		{inputError{errors.New("not a regular file")}, exitFailure},
		// An errno the command didn't name as its input: an output, or
		// something deep in it.
		{wrap(fs.ErrNotExist), exitFailure},
		{wrap(fs.ErrPermission), exitFailure},
		{wrap(localapi.ErrServiceDown), exitUnavailable},
		{wrap(localapi.ErrNotRunning), exitUnavailable},
		{wrap(agent.ErrAnotherAgent), exitTempFail},
		{errors.Join(wrap(agent.ErrAnotherAgent), errors.New("printing failed")), exitTempFail},
		{wrap(localapi.ErrMembershipUnknown), exitTempFail},
		{wrap(localapi.ErrMembershipCheckFailed), exitFailure},
		{wrap(localapi.ErrPermissionDenied), exitNoPerm},
		{wrap(localapi.ErrRootOnly), exitNoPerm},
		{wrap(agent.ErrRollbackNeedsRoot), exitNoPerm},
		{wrap(service.ErrNeedsRoot), exitNoPerm},
		{&agent.ConfigError{Err: wrap(fs.ErrNotExist)}, exitConfig},
		{inputError{&agent.ConfigError{Err: wrap(fs.ErrPermission)}}, exitConfig},
		{wrap(localapi.ErrDNSUnprotected), exitFailure},
		{wrap(localapi.ErrServerMode), exitFailure},
		{wrap(localapi.ErrPresetUnavailable), exitFailure},
		{wrap(localapi.ErrStartFailed), exitFailure},
		{wrap(localapi.ErrKillSwitchNotEnforced), exitFailure},
	} {
		if got := exitCode(c.err); got != c.code {
			t.Errorf("%v: exit %d, want %d", c.err, got, c.code)
		}
	}
}

// The old sentinels are the one needs-root type, so callers that match
// either keep working.
func TestTheNeedsRootErrorsAreOneType(t *testing.T) {
	for _, err := range []error{agent.ErrRollbackNeedsRoot, service.ErrNeedsRoot} {
		var nr *agent.NeedsRootError
		if !errors.As(wrap(err), &nr) || !errors.Is(wrap(err), err) {
			t.Errorf("%v: not an *agent.NeedsRootError, or not itself", err)
		}
	}
	if errors.Is(agent.ErrRollbackNeedsRoot, service.ErrNeedsRoot) {
		t.Error("rollback's refusal is the service's")
	}
}

// Every refusal a local API client can meet has its exit code, and every
// code there is a refusal: a new refusal without a row fails here
// instead of exiting 1 unnoticed.
func TestEveryRefusalHasAnExitCode(t *testing.T) {
	known := map[string]bool{}
	for _, r := range localapi.Refusals() {
		known[r.Code()] = true
		if _, ok := refusalExits[r.Code()]; !ok {
			t.Errorf("refusal %s has no exit code in refusalExits", r.Code())
		}
	}
	for code := range refusalExits {
		if !known[code] {
			t.Errorf("refusalExits has %s, which no refusal is", code)
		}
	}
}

// inputAt names an input by where the path error is: the input itself,
// a directory on the way to it, or a file directly in a named
// directory; nothing else, an output beside them included.
func TestInputAtNamesOnlyTheInputs(t *testing.T) {
	dir := t.TempDir()
	spec, keys := filepath.Join(dir, "in", "spec.yaml"), filepath.Join(dir, "keys")
	for _, c := range []struct {
		path string
		want bool
	}{
		{spec, true},
		{filepath.Join(dir, "in"), true},
		{keys, true},
		{filepath.Join(keys, "space.pub"), true},
		{filepath.Join(keys, "sub", "space.pub"), false},
		{filepath.Join(dir, "out", "map.bin"), false},
		{filepath.Join(dir, "in", "spec.yaml.new"), false},
	} {
		err := inputAt(&fs.PathError{Op: "open", Path: c.path, Err: fs.ErrNotExist}, []string{spec}, []string{keys})
		if got := errors.As(err, new(inputError)); got != c.want {
			t.Errorf("%s: an input %v, want %v", c.path, got, c.want)
		}
	}
	if err := inputAt(errors.New("no path"), []string{spec}, nil); errors.As(err, new(inputError)) {
		t.Error("an error without a path is an input")
	}
}

// A refusal names its code on stderr; one without a code adds nothing.
func TestCodeSuffix(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{wrap(localapi.ErrDNSUnprotected), " [dns_not_protected]"},
		{wrap(localapi.Error{}), ""},
		{errors.New("no refusal"), ""},
	} {
		if got := codeSuffix(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.err, got, c.want)
		}
	}
}
