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

// The refusals.
var (
	ErrPermissionDenied  = Error{Code: "permission_denied"}
	ErrServerMode        = Error{Code: "server_mode"}
	ErrNotRunning        = Error{Code: "not_running"}
	ErrPresetUnavailable = Error{Code: "rule_preset_unavailable"}
	ErrUnknownPreset     = Error{Code: "unknown_rule_preset"}
	ErrDNSUnprotected    = Error{Code: "dns_not_protected"}
)

// refusals are each refusal's gRPC code, which the server sends it with,
// and what a client tells a person of it.
var refusals = []struct {
	err  Error
	code codes.Code
	msg  string
}{
	{ErrPermissionDenied, codes.PermissionDenied, "permission denied: only root may do that"},
	{ErrServerMode, codes.FailedPrecondition, "this node is a server: it serves its spaces whenever it runs"},
	{ErrNotRunning, codes.Unavailable, "the node is not running"},
	{ErrPresetUnavailable, codes.FailedPrecondition, "this space can't build that preset (no chain, or no domestic list): it is kept, and enforced failing closed"},
	{ErrUnknownPreset, codes.InvalidArgument, "no such rule preset: space, everything or all-but-domestic"},
	{ErrDNSUnprotected, codes.FailedPrecondition, "connected, but DNS is not protected: the system may resolve names outside the tunnel (the service's log says why); the tunnel stays up"},
}

// ErrStartFailed is a data plane that failed to start on Connect: what
// the client wraps the failure into, not a refusal the server sends.
var ErrStartFailed = Error{Code: "start_failed"}

// startFailedPrefix begins a start failure's code, before its step.
var startFailedPrefix = ErrStartFailed.Code + ":"

// startFailed is a start failure's refusal at step: the interceptor sends
// the code alone, so the step rides in the code and the detail stays in
// the service's log.
func startFailed(step dataplane.Step) Error { return Error{Code: startFailedPrefix + string(step)} }
