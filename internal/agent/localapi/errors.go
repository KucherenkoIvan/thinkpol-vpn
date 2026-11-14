package localapi

import (
	"errors"

	"github.com/KucherenkoIvan/go-kernel/ddd"
	"google.golang.org/grpc/codes"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
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
	// ErrPermissionDenied: the caller is neither root nor in the local
	// API's group (by its credentials, or on macOS by Directory Services).
	ErrPermissionDenied = Error{Code: "permission_denied"}
	// ErrRootOnly: the call is root's, and the caller is neither root nor
	// the service's user. Its groups aren't asked: none grants the call.
	ErrRootOnly = Error{Code: "root_only"}
	// ErrMembershipUnknown: the call needs the group, and the OS didn't
	// say in time whether the caller is in it (macOS: Directory Services
	// timed out). It is refused all the same; trying again may pass.
	ErrMembershipUnknown = Error{Code: "membership_unknown"}
	// ErrMembershipCheckFailed: the call needs the group, and asking the
	// OS failed otherwise (macOS: dsmemberutil missing, failing, or
	// answering what it never says). It is refused; trying again won't
	// help until the OS is fixed.
	ErrMembershipCheckFailed = Error{Code: "membership_check_failed"}
	ErrServerMode            = Error{Code: "server_mode"}
	// ErrNotRunning: the service answers, but its node isn't running.
	ErrNotRunning        = Error{Code: "not_running"}
	ErrPresetUnavailable = Error{Code: "rule_preset_unavailable"}
	ErrUnknownPreset     = Error{Code: "unknown_rule_preset"}
	ErrDNSUnprotected    = Error{Code: "dns_not_protected"}
)

// refusals are each refusal's gRPC code, which the server sends it with,
// and what a client tells a person of it. A refusal's wording lives here
// only, with the client's own errors' below; the client's dial-time
// refusal reuses ErrPermissionDenied's ([refusalMsg]). Both permission
// refusals ([IsPermission]) begin with "permission denied", which stays;
// the rest of any message may change.
var refusals = []struct {
	err  Error
	code codes.Code
	msg  string
}{
	{ErrPermissionDenied, codes.PermissionDenied, "permission denied: the local API is for root and the members of its group"},
	{ErrRootOnly, codes.PermissionDenied, "permission denied: only root may do that; the members of the local API's group get the status and the controls"},
	{ErrMembershipUnknown, codes.Unavailable, "the service couldn't find out from the OS whether you're in the local API's group: try again"},
	{ErrMembershipCheckFailed, codes.Internal, "the service couldn't ask the OS whether you're in the local API's group: the OS's directory service failed, and trying again won't help until it is fixed"},
	{ErrServerMode, codes.FailedPrecondition, "this node is a server: it serves its spaces whenever it runs"},
	{ErrNotRunning, codes.Unavailable, "the node is not running"},
	{ErrPresetUnavailable, codes.FailedPrecondition, "this space can't build that preset (no chain, or no domestic list): it is kept, and enforced failing closed"},
	{ErrUnknownPreset, codes.InvalidArgument, "no such rule preset: space, everything or all-but-domestic"},
	{ErrDNSUnprotected, codes.FailedPrecondition, "connected, but DNS is not protected: the system may resolve names outside the tunnel; the tunnel stays up"},
}

// Refusals are every refusal a client may find in an error (errors.Is):
// those the server sends, and the client's own, [ErrServiceDown],
// [ErrStartFailed] and [ErrKillSwitchNotEnforced].
func Refusals() []Error {
	out := []Error{ErrServiceDown, ErrStartFailed, ErrKillSwitchNotEnforced}
	for _, r := range refusals {
		out = append(out, r.err)
	}
	return out
}

// refusalMsg is what a client tells a person of e.
func refusalMsg(e Error) string {
	for _, r := range refusals {
		if r.err == e {
			return r.msg
		}
	}
	return e.Code
}

// IsPermission reports whether err is a refusal by who the caller is
// ([ErrPermissionDenied] or [ErrRootOnly]), not a failure to find out
// ([ErrMembershipUnknown], [ErrMembershipCheckFailed]). A UI that acts on the refusal tells the two
// apart with errors.Is: the first asks for the group, the second for root.
func IsPermission(err error) bool {
	return errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrRootOnly)
}

// ErrServiceDown is nothing listening at the local API's socket: what the
// client finds when it dials, not a refusal the server sends.
var ErrServiceDown = Error{Code: "service_down"}

// What the client tells a person of its own errors: [ErrServiceDown],
// [ErrStartFailed] at a step and [ErrKillSwitchNotEnforced] with its
// reason. serviceDownMsg begins "the thinkpol service", which stays (the
// lab checks it); the rest may change.
const (
	serviceDownMsg           = "the thinkpol service is not running"
	startFailedMsg           = "starting the data plane failed at step %q"
	killSwitchNotEnforcedMsg = "the setting is kept, but the kill switch is not enforced: %s"
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

// ErrKillSwitchNotEnforced is a kill switch toggle the node stored and
// acted on while the kill switch is left not as meant: what the client
// wraps the refusal into, its reason in the message.
var ErrKillSwitchNotEnforced = Error{Code: "kill_switch_not_enforced"}

// killSwitchNotEnforcedPrefix begins the refusal's code, before its
// reason (agent.KillSwitchError).
var killSwitchNotEnforcedPrefix = ErrKillSwitchNotEnforced.Code + ":"

// killSwitchNotEnforced is the refusal for reason: like a start failure's,
// the reason rides in the code.
func killSwitchNotEnforced(reason agent.KillSwitchError) Error {
	return Error{Code: killSwitchNotEnforcedPrefix + string(reason)}
}
