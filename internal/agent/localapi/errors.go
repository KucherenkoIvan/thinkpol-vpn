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
	ErrPermissionDenied   = Error{Code: "permission_denied"}
	ErrServerMode         = Error{Code: "server_mode"}
	ErrNotRunning         = Error{Code: "not_running"}
	ErrPresetsUnavailable = Error{Code: "rule_presets_unavailable"}
	ErrUnknownPreset      = Error{Code: "unknown_rule_preset"}

	errorCodes = map[Error]codes.Code{
		ErrPermissionDenied:   codes.PermissionDenied,
		ErrServerMode:         codes.FailedPrecondition,
		ErrNotRunning:         codes.Unavailable,
		ErrPresetsUnavailable: codes.Unimplemented,
		ErrUnknownPreset:      codes.InvalidArgument,
	}
)
