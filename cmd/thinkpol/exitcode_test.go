package main

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
)

// What a command fails with maps to one code, however it is wrapped:
// the refusals the local API names before the file system's errors they
// may carry, and 1 for anything unnamed.
func TestExitCodeMapsEachFailure(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("context: %w", err) }
	for _, c := range []struct {
		err  error
		code int
	}{
		{nil, exitOK},
		{errors.New("anything else"), exitFailure},
		{wrap(errUsage), exitUsage},
		{argsError{errors.New("a removed form")}, exitUsage},
		{wrap(localapi.ErrUnknownPreset), exitUsage},
		{wrap(fs.ErrNotExist), exitNoInput},
		{wrap(localapi.ErrServiceDown), exitUnavailable},
		{wrap(localapi.ErrNotRunning), exitUnavailable},
		{wrap(agent.ErrAnotherAgent), exitTempFail},
		{errors.Join(wrap(agent.ErrAnotherAgent), errors.New("printing failed")), exitTempFail},
		{wrap(localapi.ErrMembershipUnknown), exitTempFail},
		{wrap(localapi.ErrPermissionDenied), exitNoPerm},
		{wrap(localapi.ErrRootOnly), exitNoPerm},
		{wrap(agent.ErrRollbackNeedsRoot), exitNoPerm},
		{wrap(service.ErrNeedsRoot), exitNoPerm},
		{wrap(fs.ErrPermission), exitNoPerm},
		{&agent.ConfigError{Err: wrap(fs.ErrNotExist)}, exitConfig},
		{wrap(localapi.ErrDNSUnprotected), exitFailure},
		{wrap(localapi.ErrServerMode), exitFailure},
		{wrap(localapi.ErrPresetUnavailable), exitFailure},
		{wrap(localapi.ErrStartFailed), exitFailure},
	} {
		if got := exitCode(c.err); got != c.code {
			t.Errorf("%v: exit %d, want %d", c.err, got, c.code)
		}
	}
}
