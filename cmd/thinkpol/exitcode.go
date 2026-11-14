package main

import (
	"errors"
	"flag"
	"io/fs"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/service"
)

// The exit codes, BSD sysexits.h's (docs/design/api-overview.md,
// "Verdicts"): a contract scripts branch on. exitCode alone picks one;
// no command exits with a number of its own.
const (
	exitOK          = 0
	exitFailure     = 1  // not reached, even failing closed; a node's status is still printed
	exitUsage       = 64 // EX_USAGE: bad arguments
	exitNoInput     = 66 // EX_NOINPUT: a named input is missing
	exitUnavailable = 69 // EX_UNAVAILABLE: the service isn't running
	exitTempFail    = 75 // EX_TEMPFAIL: busy, try again
	exitNoPerm      = 77 // EX_NOPERM: permission denied
	exitConfig      = 78 // EX_CONFIG: bad configuration
)

// exitCodes maps what a command failed with to its code, first match
// wins: a refusal the local API names comes before the file system's
// errors a command may also wrap.
var exitCodes = []struct {
	code int
	is   func(error) bool
}{
	{exitOK, func(err error) bool { return errors.Is(err, flag.ErrHelp) }},
	{exitUsage, func(err error) bool {
		return errors.Is(err, errUsage) || errors.Is(err, errUsagePrinted) || errors.As(err, new(argsError)) ||
			errors.Is(err, localapi.ErrUnknownPreset)
	}},
	{exitConfig, func(err error) bool { return errors.As(err, new(*agent.ConfigError)) }},
	{exitTempFail, func(err error) bool {
		return errors.Is(err, agent.ErrAnotherAgent) || errors.Is(err, localapi.ErrMembershipUnknown)
	}},
	{exitNoPerm, func(err error) bool {
		return localapi.IsPermission(err) || errors.Is(err, agent.ErrRollbackNeedsRoot) || errors.Is(err, service.ErrNeedsRoot)
	}},
	{exitUnavailable, func(err error) bool {
		return errors.Is(err, localapi.ErrServiceDown) || errors.Is(err, localapi.ErrNotRunning)
	}},
	{exitNoPerm, func(err error) bool { return errors.Is(err, fs.ErrPermission) }},
	{exitNoInput, func(err error) bool { return errors.Is(err, fs.ErrNotExist) }},
}

// exitCode is the code a command that returned err exits with: 0 for
// nil, 1 for anything exitCodes doesn't name.
func exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	for _, c := range exitCodes {
		if c.is(err) {
			return c.code
		}
	}
	return exitFailure
}

// argsError is a command's arguments refused with a reason (exit 64),
// printed instead of the synopsis errUsage prints.
type argsError struct{ error }

func (e argsError) Unwrap() error { return e.error }
