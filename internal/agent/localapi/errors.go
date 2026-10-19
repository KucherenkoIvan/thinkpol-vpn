package localapi

import (
	"github.com/KucherenkoIvan/go-kernel/ddd"
	"google.golang.org/grpc/codes"
)

// Error is an expected refusal, sent to clients by its code.
type Error struct {
	ddd.DomainError
	Code string
}

func (e Error) Error() string { return e.Code }

// The refusals and the gRPC codes they go out with.
var (
	ErrPermissionDenied  = Error{Code: "permission_denied"}
	ErrServerMode        = Error{Code: "server_mode"}
	ErrNotRunning        = Error{Code: "not_running"}
	ErrPresetUnavailable = Error{Code: "rule_preset_unavailable"}
	ErrUnknownPreset     = Error{Code: "unknown_rule_preset"}
	ErrDNSUnprotected    = Error{Code: "dns_not_protected"}
	// ErrStartFailed is a data plane that failed to start on Connect; the
	// code a client sees carries the step (startFailed), the only part of
	// the failure safe to show.
	ErrStartFailed = Error{Code: "start_failed"}

	errorCodes = map[Error]codes.Code{
		ErrPermissionDenied:  codes.PermissionDenied,
		ErrServerMode:        codes.FailedPrecondition,
		ErrNotRunning:        codes.Unavailable,
		ErrPresetUnavailable: codes.FailedPrecondition,
		ErrUnknownPreset:     codes.InvalidArgument,
		ErrDNSUnprotected:    codes.FailedPrecondition,
	}
)

// startFailedPrefix begins a start failure's code, before its step.
const startFailedPrefix = "start_failed:"

// startFailed is a start failure's refusal at step: the interceptor sends
// the code alone, so the step rides in it; the detail is the service's
// log's alone.
func startFailed(step string) Error { return Error{Code: startFailedPrefix + step} }
