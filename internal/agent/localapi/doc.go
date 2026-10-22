// Package localapi is the node agent's local service API (DESIGN.md "The
// local API"): a gRPC service (proto/thinkpol/localapi/v1) on a Unix
// socket that the CLI and the tray app use to see and control the node
// running on the same machine. `thinkpol up` serves it as one of its app
// adapters ([Adapter]), next to the node's.
//
// # What it serves
//
//   - GetStatus, and WatchStatus as a stream: the node's mode and
//     connection, its space and map version, whether it was removed from
//     the space, its health and problems, its rule preset; a running data
//     plane's MTU and IPv6 state (and why IPv6 is off), the last Apply's
//     failed step, its counters, its peers with the entry each one's
//     packets leave through, its neighbors and their links, its egresses,
//     and what the map held that the node skipped; on a server, its
//     workers, its uplink and its public listeners.
//   - Connect and Disconnect.
//   - ListSpaces: the enrolled spaces (one per node until a device enrolls
//     in several, TP-049).
//   - SetRulePreset.
//   - TailLogs: the agent's in-memory log, its last lines and then, if
//     asked, what follows.
//   - Diagnose: a snapshot of what the node changed on the host and what
//     the host shows of it (below).
//
// Connect and Disconnect bring a device's data plane up and down while the
// service keeps running and keeps following its space's maps
// ([agent.Node.Connect]). Connect returns once the data plane is up, or
// the step its start failed at; a device connected while its OS may
// resolve names outside the node's resolver hears `dns_not_protected`.
// `thinkpol up -connect=false` starts a device disconnected. A server
// serves its spaces whenever it runs: it reports its workers and public
// listeners and refuses Connect, Disconnect and SetRulePreset.
//
// # Where the socket is
//
// The socket is [agent.Config.APISocket] (-api-socket), by default
// [agent.DefaultAPISocket]: /run/thinkpol-api/api.sock on Linux, and on
// macOS /private/var/db/thinkpol-api/api.sock. Not under macOS's /var/run,
// which fails the parent check below (package trusteddir says why a
// directory others can write to can't be trusted), and beside netcfg's /private/var/db/thinkpol rather than in it:
// that one is 0700, so the group couldn't reach the socket. Windows will
// use a named pipe (TP-047); until then [Listen] refuses there. An empty
// socket path serves no API.
//
// # Who may do what
//
// The socket's directory is the first gate ([Listen]). The service creates
// it 0750, owned by its user (root) with the API's group, `thinkpol` by
// default (-api-group, a name or a gid), or 0700 if there is no such group,
// in which case the API is root's only and the service warns. The group is
// looked up in /etc/group, and on macOS also in Directory Services
// (dscl). The directory's parent must be root's (or the service user's)
// and writable by no one else. A real directory of the service's user left
// from an earlier run gets the right group and mode through its own
// descriptor; a symlink or another user's directory is refused. Anyone
// outside the group gets "permission denied" when they connect. The socket
// itself is 0660 with the group (0600 without one). A lock file next to it
// ([LockFile]) keeps two services from taking the socket over at once, and
// a socket left by a service that crashed is removed only when nothing
// answers on it.
//
// Every call then checks the caller again, by the credentials the kernel
// recorded at connect time (SO_PEERCRED and SO_PEERGROUPS on Linux,
// LOCAL_PEERCRED on macOS), against the call's level ([Policy]): root and
// the service's own user may do everything; members of the group see the
// status and the spaces, control the node (Connect, Disconnect,
// SetRulePreset) and take the diagnostics without their host parts; the
// log is root's only, because its debug lines may quote the map. A call not listed needs everything. Not yet on macOS: the
// per-call check sees only the groups the caller's process got at login,
// and only the first 16 of those (LOCAL_PEERCRED's xucred), so a member
// added since, or one whose `thinkpol` group is past the first 16, is
// refused every call though the directory's gate lets them through; see
// TP-094. There is no read-only tier for other users: they can't reach the
// socket at all.
//
// At most [MaxConns] (32) connections and [MaxStreams] (16) calls per
// connection are served; a client opening more waits. All status watchers
// share one snapshot, taken at most every 250 ms.
//
// # The API never takes the VPN down
//
// If it can't serve (a refused directory, a broken socket), the node logs
// it as an error and runs on without it, trying again every
// [DefaultRetryAfter] (10 s); only the status and control are unavailable
// meanwhile.
//
// # Rule presets
//
// A preset chosen through SetRulePreset is stored by the service in the
// device's state directory ([agent.LocalRulesFile], rules.local, next to
// the device's own rules), then handed to the engine; nothing else writes
// it (see [agent.Node.SetRulePreset]). It is read like the node's other
// files, and one that can't be read or parsed stops the node from starting
// rather than reading as no rules. A preset the map can't build is kept
// and enforced failing closed, and the API says so
// (`rule_preset_unavailable`, and the status).
//
// # Diagnostics
//
// Diagnose (`thinkpol diag`, `-o FILE` to write it at mode 0600) is the
// evidence a device run records and is judged by afterwards (TP-091): one
// JSON snapshot, protojson of [localapiv1.Diagnostics], in which every
// part says why if the agent couldn't read it (`unreadable`), so "nothing
// there" and "couldn't look" stay apart. Its schema has a version,
// [DiagSchemaVersion], bumped when a field is removed or changes meaning;
// a field added doesn't bump it, and a reader ignores fields it doesn't
// know. Taking it changes nothing on the host. It holds:
//
//   - the schema version, when it was taken, the agent's OS and version;
//   - the status GetStatus serves;
//   - the overlay's TUN as the host reports it (its name, index, MTU, up
//     and running flags, addresses), unreadable while the data plane is
//     down;
//   - the routes (every table) and policy rules the agent's owners hold,
//     as the kernel reports them ([netcfg.Inspect]);
//   - the IPv6 leak guard as the host holds it
//     ([firewall.InspectIPv6Guard]): on Linux the nftables table's flags,
//     chain, rules with their counters and exempt set (macOS's isn't read
//     yet: it says so).
//
// The routes, rules and guard are read from the host whatever the data
// plane's state, so a snapshot after a crash or a stop shows what was
// left. They name public addresses (the entries', the direct
// destinations', the gateway's), so they are root's: the group's
// snapshot has each of them unreadable, "root only", and the agent
// doesn't read them for it.
//
// The snapshot holds no key, token or session id: what it carries comes
// from the status, which holds none, and from reading the host, which
// holds none of the node's. A test walks its schema for fields named for
// one, and another looks for a device's keys and its links' credentials
// in a real node's snapshot. The file is written beside its path and
// renamed over it, so root writing into a directory others can write to
// replaces a symlink there instead of following it.
//
// # What it reports
//
// Nothing the API reports is a public address, a key or a secret (PRD
// S1, S4), but Diagnose's root-only parts, which name public addresses: nodes and spaces are opaque ids, addresses are the overlay's,
// links name their endpoint by its index, and a server's listeners are
// shown without their addresses. Failures are named from fixed
// vocabularies: refusals are [Error] values (go-kernel ddd.DomainError
// values that grpckit's interceptor sends by their code), and a failed
// Connect names only its step (`start_failed:<step>`), the detail going to
// the node's log. A worker's last exit is shown as the supervisor recorded
// it, sanitized. Strings that come from the map or a transport are
// sanitized before they leave ([agent.Sanitize]), and clients sanitize
// every string they receive before showing it ([Client]): worker output
// and anything else from the service is never trusted with a terminal.
package localapi
