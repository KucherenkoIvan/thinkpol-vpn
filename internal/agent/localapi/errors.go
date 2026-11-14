package localapi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KucherenkoIvan/go-kernel/ddd"
	"google.golang.org/grpc/codes"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
)

// Error is an expected refusal, sent to clients by its code. The code
// can't be set outside this file's list: every Error is one of the values
// declared below, all of them in [refusals] (which [Refusals] returns), or
// one of them with a detail ([Error.withDetail]); a test fails on an Error
// built anywhere else in the package.
type Error struct {
	ddd.DomainError
	code string
}

func (e Error) Error() string { return e.code }

// Code is what the server sends the refusal as.
func (e Error) Code() string { return e.code }

// withDetail is e with detail riding in its code (`start_failed:tun`):
// the interceptor sends the code alone, so the detail can't go beside it.
// A client finds e in it ([Error.detail]).
func (e Error) withDetail(detail string) Error { return Error{code: e.code + ":" + detail} }

// detail is the detail of code, when code is e's with one.
func (e Error) detail(code string) (string, bool) { return strings.CutPrefix(code, e.code+":") }

// The refusals.
var (
	// ErrPermissionDenied: the caller is neither root nor in the local
	// API's group (by its credentials, or on macOS by Directory Services).
	ErrPermissionDenied = Error{code: "permission_denied"}
	// ErrRootOnly: the call is root's, and the caller is neither root nor
	// the service's user. Its groups aren't asked: none grants the call.
	ErrRootOnly = Error{code: "root_only"}
	// ErrMembershipUnknown: the call needs the group, and the OS didn't
	// say in time whether the caller is in it (macOS: Directory Services
	// timed out). It is refused all the same; trying again may pass.
	ErrMembershipUnknown = Error{code: "membership_unknown"}
	// ErrMembershipCheckFailed: the call needs the group, and asking the
	// OS failed otherwise (macOS: dsmemberutil missing, failing, or
	// answering what it never says). It is refused; trying again won't
	// help until the OS is fixed.
	ErrMembershipCheckFailed = Error{code: "membership_check_failed"}
	ErrServerMode            = Error{code: "server_mode"}
	// ErrNotRunning: the service answers, but its node isn't running.
	ErrNotRunning        = Error{code: "not_running"}
	ErrPresetUnavailable = Error{code: "rule_preset_unavailable"}
	ErrUnknownPreset     = Error{code: "unknown_rule_preset"}
	ErrDNSUnprotected    = Error{code: "dns_not_protected"}
	// ErrStartFailed is a data plane that failed to start on Connect, sent
	// with its step as the detail (`start_failed:<step>`); the failure
	// itself stays in the service's log.
	ErrStartFailed = Error{code: "start_failed"}
	// ErrKillSwitchNotEnforced is a kill switch toggle the node stored and
	// acted on while the kill switch is left not as meant, sent with the
	// reason (agent.KillSwitchError) as the detail.
	ErrKillSwitchNotEnforced = Error{code: "kill_switch_not_enforced"}
	// ErrServiceDown is nothing listening at the local API's socket: what
	// the client finds when it dials, never sent by the server.
	ErrServiceDown = Error{code: "service_down"}
)

// refusals are every refusal: its gRPC code, which the server sends it
// with, and what a client tells a person of it, a detail filling the %s
// of a refusal sent with one (detailed). A detailed refusal's code varies,
// so it goes as grpckit's default, FailedPrecondition, the code its row
// says; service_down's is never sent. A refusal's wording lives here
// only; the client's dial-time refusal reuses ErrPermissionDenied's.
// Both permission refusals ([IsPermission]) begin with "permission
// denied", and service_down's with "the thinkpol service" (the lab checks
// it), which stay; the rest of any message may change.
var refusals = []struct {
	err      Error
	code     codes.Code
	msg      string
	detailed bool
}{
	{ErrPermissionDenied, codes.PermissionDenied, "permission denied: the local API is for root and the members of its group", false},
	{ErrRootOnly, codes.PermissionDenied, "permission denied: only root may do that; the members of the local API's group get the status and the controls", false},
	{ErrMembershipUnknown, codes.Unavailable, "the service couldn't find out from the OS whether you're in the local API's group: try again", false},
	{ErrMembershipCheckFailed, codes.Internal, "the service couldn't ask the OS whether you're in the local API's group: the OS's directory service failed, and trying again won't help until it is fixed", false},
	{ErrServerMode, codes.FailedPrecondition, "this node is a server: it serves its spaces whenever it runs", false},
	{ErrNotRunning, codes.Unavailable, "the node is not running", false},
	{ErrPresetUnavailable, codes.FailedPrecondition, "this space can't build that preset (no chain, or no domestic list): it is kept, and enforced failing closed", false},
	{ErrUnknownPreset, codes.InvalidArgument, "no such rule preset: space, everything or all-but-domestic", false},
	{ErrDNSUnprotected, codes.FailedPrecondition, "connected, but DNS is not protected: the system may resolve names outside the tunnel; the tunnel stays up", false},
	{ErrStartFailed, codes.FailedPrecondition, "starting the data plane failed at step %q", true},
	{ErrKillSwitchNotEnforced, codes.FailedPrecondition, "the setting is kept, but the kill switch is not enforced: %s", true},
	{ErrServiceDown, codes.Unavailable, "the thinkpol service is not running", false},
}

// Refusals are every refusal a client may find in an error (errors.Is):
// those the server sends, and the client's own [ErrServiceDown].
func Refusals() []Error {
	out := make([]Error, 0, len(refusals))
	for _, r := range refusals {
		out = append(out, r.err)
	}
	return out
}

// refusalMsg is what a client tells a person of e, sent with detail if
// it has one.
func refusalMsg(e Error, detail string) string {
	for _, r := range refusals {
		if r.err == e {
			if r.detailed {
				return fmt.Sprintf(r.msg, agent.Sanitize(detail))
			}
			return r.msg
		}
	}
	return e.code
}

// IsPermission reports whether err is a refusal by who the caller is
// ([ErrPermissionDenied] or [ErrRootOnly]), not a failure to find out
// ([ErrMembershipUnknown], [ErrMembershipCheckFailed]). A UI that acts on the refusal tells the two
// apart with errors.Is: the first asks for the group, the second for root.
func IsPermission(err error) bool {
	return errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrRootOnly)
}

// startFailed is a start failure's refusal at step.
func startFailed(step dataplane.Step) Error { return ErrStartFailed.withDetail(string(step)) }

// killSwitchNotEnforced is the refusal for reason.
func killSwitchNotEnforced(reason agent.KillSwitchError) Error {
	return ErrKillSwitchNotEnforced.withDetail(string(reason))
}
