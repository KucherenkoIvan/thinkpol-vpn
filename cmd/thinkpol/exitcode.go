package main

import (
	"errors"
	"flag"
	"io/fs"
	"path/filepath"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/localapi"
)

// The exit codes, BSD sysexits.h's (docs/design/api-overview.md,
// "Verdicts"): a contract scripts branch on. exitCode alone picks one;
// no command exits with a number of its own.
const (
	exitOK          = 0
	exitFailure     = 1  // not reached, even failing closed; a change through the local API prints the status (printOutcome)
	exitUsage       = 64 // EX_USAGE: bad arguments
	exitNoInput     = 66 // EX_NOINPUT: a named input is missing
	exitUnavailable = 69 // EX_UNAVAILABLE: the service isn't running
	exitTempFail    = 75 // EX_TEMPFAIL: busy, try again
	exitNoPerm      = 77 // EX_NOPERM: permission denied
	exitConfig      = 78 // EX_CONFIG: bad configuration
)

// exitCodes maps what a command failed with to its code, first match
// wins. Only typed errors and sentinels are matched, never an errno
// alone: a missing file or a refused one deep in a command is 1, unless
// the command named it as its input (inputError). Their order is the
// tie-break for an error that is two of them: a ConfigError wrapping a
// named input's ENOENT stays 78. The local API's refusals come last
// (refusalExits), by code.
var exitCodes = []struct {
	code int
	is   func(error) bool
}{
	{exitOK, func(err error) bool { return errors.Is(err, flag.ErrHelp) }},
	{exitUsage, func(err error) bool {
		return errors.Is(err, errUsage) || errors.Is(err, errUsagePrinted) || errors.As(err, new(argsError))
	}},
	{exitConfig, func(err error) bool { return errors.As(err, new(*agent.ConfigError)) }},
	{exitTempFail, func(err error) bool { return errors.Is(err, agent.ErrAnotherAgent) }},
	{exitNoPerm, func(err error) bool { return errors.As(err, new(*agent.NeedsRootError)) }},
	{exitNoInput, func(err error) bool { return errors.As(err, new(inputError)) && errors.Is(err, fs.ErrNotExist) }},
	{exitNoPerm, func(err error) bool { return errors.As(err, new(inputError)) && errors.Is(err, fs.ErrPermission) }},
}

// refusalExits is each local API refusal's code (localapi.Refusals, which
// a test holds this to: a new refusal without a row fails it).
var refusalExits = map[string]int{
	localapi.ErrPermissionDenied.Code():      exitNoPerm,
	localapi.ErrRootOnly.Code():              exitNoPerm,
	localapi.ErrMembershipUnknown.Code():     exitTempFail,
	localapi.ErrMembershipCheckFailed.Code(): exitFailure,
	localapi.ErrServerMode.Code():            exitFailure,
	localapi.ErrNotRunning.Code():            exitUnavailable,
	localapi.ErrPresetUnavailable.Code():     exitFailure,
	localapi.ErrPresetNotEnforced.Code():     exitFailure,
	localapi.ErrPresetIncomplete.Code():      exitFailure,
	localapi.ErrUnknownPreset.Code():         exitUsage,
	localapi.ErrDNSUnprotected.Code():        exitFailure,
	localapi.ErrServiceDown.Code():           exitUnavailable,
	localapi.ErrStartFailed.Code():           exitFailure,
	localapi.ErrKillSwitchNotEnforced.Code(): exitFailure,
}

// exitCode is the code a command that returned err exits with: 0 for
// nil, 1 for anything exitCodes and refusalExits don't name.
func exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	for _, c := range exitCodes {
		if c.is(err) {
			return c.code
		}
	}
	var refusal localapi.Error
	if errors.As(err, &refusal) {
		if code, ok := refusalExits[refusal.Code()]; ok {
			return code
		}
	}
	return exitFailure
}

// argsError is a command's arguments refused with a reason (exit 64),
// printed instead of the synopsis errUsage prints.
type argsError struct{ error }

func (e argsError) Unwrap() error { return e.error }

// inputError is a failure to open an input the command line names (a
// spec, a map, a key directory, a state directory): 66 when it is
// missing, 77 when the caller may not read it, else 1.
type inputError struct{ error }

func (e inputError) Unwrap() error { return e.error }

// input is err from opening a named input, as an inputError.
func input(err error) error {
	if err == nil {
		return nil
	}
	return inputError{err}
}

// inputAt is err as an inputError when it is a path error at one of paths,
// on the way to one (a directory above it), or, for dirs, at a file
// directly in one: what a command that also writes, or reads more than
// its named inputs, failed to open of those. Any other error is as it is.
func inputAt(err error, paths, dirs []string) error {
	var pe *fs.PathError
	if err == nil || !errors.As(err, &pe) {
		return err
	}
	at, aerr := filepath.Abs(pe.Path)
	if aerr != nil {
		return err
	}
	for _, p := range append(paths, dirs...) {
		if p, perr := filepath.Abs(p); perr == nil && within(at, p) {
			return inputError{err}
		}
	}
	for _, d := range dirs {
		if d, derr := filepath.Abs(d); derr == nil && filepath.Dir(at) == d {
			return inputError{err}
		}
	}
	return err
}

// within reports whether path is p or a directory above it.
func within(path, p string) bool {
	for {
		if path == p {
			return true
		}
		up := filepath.Dir(p)
		if up == p {
			return false
		}
		p = up
	}
}
