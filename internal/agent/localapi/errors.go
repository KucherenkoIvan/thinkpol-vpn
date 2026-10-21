package localapi

import (
	"github.com/KucherenkoIvan/go-kernel/ddd"
	"google.golang.org/grpc/codes"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
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

	errorCodes = map[Error]codes.Code{
		ErrPermissionDenied:  codes.PermissionDenied,
		ErrServerMode:        codes.FailedPrecondition,
		ErrNotRunning:        codes.Unavailable,
		ErrPresetUnavailable: codes.FailedPrecondition,
		ErrUnknownPreset:     codes.InvalidArgument,
		ErrDNSUnprotected:    codes.FailedPrecondition,
	}
)

// ErrStartFailed is a data plane that failed to start on Connect: what
// the client wraps the failure into, not a refusal the server sends.
var ErrStartFailed = Error{Code: "start_failed"}

// startFailedPrefix begins a start failure's code, before its step.
var startFailedPrefix = ErrStartFailed.Code + ":"

// startFailed is a start failure's refusal at step: the interceptor sends
// the code alone, so the step rides in the code and the detail stays in
// the service's log.
func startFailed(step dataplane.Step) Error { return Error{Code: startFailedPrefix + string(step)} }
