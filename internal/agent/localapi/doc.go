// Package localapi is the node agent's local service API
// (docs/design/desktop-client.md "The local API"): a gRPC service
// (proto/thinkpol/localapi/v1) on a Unix socket that the CLI and the tray app use to see and control the node
// running on the same machine. `thinkpol up` serves it as one of its app
// adapters ([Adapter]), next to the node's.
//
// # What it serves
//
//   - GetStatus, and WatchStatus as a stream: the node's mode and
//     connection, its space and map version, whether it was removed from
//     the space, its health and problems, its rule preset and
//     connect-on-boot, and the JSON schema's version; a running data
//     plane's TUN, MTU and IPv6 state (and why IPv6 is off), the last Apply's
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
// `thinkpol up -connect=false` starts a device disconnected; under the
// service the device's connect-on-boot decides a boot's first start
// (SetConnectOnBoot sets it, from the next boot; `thinkpol
// connect-on-boot on|off`, GetStatus shows it), and a later start
// in the same boot comes back as the last Connect or Disconnect left it
// ([agent.ConnectRecord]). A server
// serves its spaces whenever it runs: it reports its workers and public
// listeners and refuses Connect, Disconnect, SetRulePreset and
// SetConnectOnBoot.
//
// # Where the socket is
//
// The socket is [agent.Config.APISocket] (-api-socket), by default
// [agent.DefaultAPISocket]: /run/thinkpol-api/api.sock on Linux, and on
// macOS /private/var/db/thinkpol-api/api.sock. Not under macOS's /var/run,
// which fails the parent check below (package trusteddir says why a
// directory others can write to can't be trusted), and beside netcfg's
// /private/var/db/thinkpol rather than in it: that one is 0700, so the
// group couldn't reach the socket. Windows will
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
// status and the spaces, control the node (Connect, Disconnect), set the
// member's toggles (SetRulePreset, SetConnectOnBoot) and take the diagnostics without their host parts; the
// log is root's only, because its debug lines may quote the map. A call
// not listed needs everything. On macOS the recorded groups are only those
// the caller's process got at login, and only the first 16 of those
// (LOCAL_PEERCRED's xucred), while the directory's gate asks Directory
// Services. So when a caller other than root or the service's user lacks
// the group in its recorded groups, [Policy.Membership] asks Directory
// Services too (`dsmemberutil checkmembership -u <uid> -g <gid>`, by
// numbers): a member added since login, or one whose `thinkpol` group is
// past the first 16, gets the group's rights. Each lookup is bounded by 3
// s, whoever waits for it, and runs one at a time; its answer is kept 10 s
// per uid and group (at most 64 answers), even when the caller that
// started it has left. A lookup that fails or times out, or an answer
// dsmemberutil doesn't word as expected, is not a member, and is kept 5 s
// (longer than a lookup may take) so that callers are refused at once
// while Directory Services is down. A root-only call isn't looked up: no
// group grants it.
// Linux needs none of this: SO_PEERGROUPS and the file system both use the
// process's groups.
//
// Removal from the group takes effect at the user's next login when the
// caller's session carries the group: both gates read the recorded groups
// first, on every OS. Only a caller whose session never carried it (macOS,
// found through Directory Services) loses control within the 10 s its
// answer is kept. A stream (WatchStatus) is checked when it opens, so an
// open one keeps flowing until the client reconnects, on every OS.
//
// A refusal says which case it is: permission_denied (neither root nor in
// the group), root_only (not root or the service's user, and the call is
// root's) or membership_unknown (the call needs the group and Directory
// Services couldn't say; refused all the same, with codes.Unavailable, to
// be tried again). A caller that hangs up during the lookup isn't refused:
// it gets its context's end, logged at debug; when that end is the
// caller's own deadline, grpckit also logs "rpc deadline exceeded" at
// warn. The wording is in errors.go
// only ([refusals], and the client's own errors' beside it), which the
// client's dial-time refusal shares, and none of it points at the log,
// which only root may read; both permission refusals begin with
// "permission denied". Every refusal is logged with its method and code;
// one with credentials also has the caller's uid, the level the call
// needed, the group it was checked against (if there is one) and how many
// groups the kernel recorded (not which ones), plus, if the group was
// looked up, the level the caller had and why Directory Services couldn't
// answer, if it couldn't. membership_unknown is logged at warn, the others
// at info.
// There is no read-only tier for other users: they can't reach the
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
// device file ([agent.DeviceFile], device.json, with the device's own
// rules and connect-on-boot), then handed to the engine; nothing else
// writes it (see [agent.Node.SetRulePreset]). It is read like the node's
// other files, and one that can't be read or parsed stops the node from
// starting rather than reading as no settings. A preset the map can't build is kept
// and enforced failing closed, and the API says so
// (`rule_preset_unavailable`, and the status).
//
// # Diagnostics
//
// Diagnose (`thinkpol diag`) is the evidence a device run records and is
// judged by afterwards (TP-091): one snapshot, [localapiv1.Diagnostics],
// in which every part says why if the agent couldn't read it
// (`unreadable`, free text, with nothing else set), so "nothing there"
// and "couldn't look" stay apart. It records; it doesn't judge: the
// guard's own check of pf comes with its evidence.
//
// Its JSON ([WriteDiagnostics]) is in the convention below, and part of
// the v1 contract; only a guard's `present` is left out, when it couldn't
// be told (protojson omits an unset proto3 optional field even then).
// Taking it changes nothing on the host. It holds:
//
//   - the schema version, when it was taken, the agent's OS and version,
//     and `host_parts`: whether the caller got the host parts;
//   - the status GetStatus serves;
//   - a device's TUN as the host reports it ([netcfg.InspectInterface]:
//     name, index, MTU, up and running flags, addresses), unreadable while
//     the data plane is down, and on a server, whose data planes run in
//     its workers;
//   - the data plane's last Apply: when it started, how long it took, the
//     step it failed at, and its steps with their timings
//     ([dataplane.Engine.LastApply]);
//   - the routes (every table) and policy rules, with their actions, the
//     agent's owners hold, as the kernel reports them ([netcfg.Inspect]);
//     on macOS also the RTF_PROTO2 routes no owner's record names;
//   - the IPv6 leak guard as the host holds it
//     ([firewall.InspectIPv6Guard]): on Linux the nftables table's flags,
//     chains, rules (rendered nft-like) with their counters and exempt
//     set; on macOS the pf anchor's rules with their counters, its exempt
//     table, pf's enabled state, the guard's check of the main ruleset with
//     its lines up to the hook, every skipped interface and the anchors
//     before the guard's, and the guard's `pfctl -E` reference and whether
//     pf still holds it;
//   - the resolvers the host uses, for the overlay's names and the rest
//     ([dns.Inspect]): resolv.conf and systemd-resolved's links on Linux,
//     `scutil --dns` on macOS;
//   - `service_drop_ins`: drop-ins for the service's systemd unit
//     (thinkpol.service.d/*.conf and service.d/*.conf), by path, unsupported and reported
//     ([agent.DropInReport]); none on macOS. Not a host part: paths only,
//     the group gets them too;
//   - `last_run`: what the previous run under a device's service left on
//     its stderr ([agent.LastRun]: a panic's or a fatal error's trace, or
//     the error it exited with), its head line by line, up to 64 KiB
//     (`truncated` says there was more); empty after a clean stop and on a
//     server. Root's, like the host parts: a panic's message may name a
//     public address, so the group's snapshot has it unreadable, "root
//     only", when there is one. The status's `last_run_crashed` says
//     there is one, to the group too (`status` prints a "last run" line),
//     and `last_run_unreadable` that there was a file it didn't read
//     (`unreadable` says why, to root).
//
// The routes, rules, guard and resolvers are read from the host whatever
// the data plane's state, so a snapshot after a crash or a stop shows
// what was left. They name public addresses (the entries', the direct
// destinations', the gateway's, the upstreams'), so they are root's: the
// group's snapshot has each of them unreadable, "root only", and the
// agent doesn't read them for it.
//
// The snapshot holds no key, token or session id: what it carries comes
// from the status, which holds none, and from reading the host, which
// holds none of the node's. The pf reference shows by its pid; its token
// stays in the guard's record, whose errors never quote it. A test walks
// the schema for fields named for a secret, and another looks for a
// device's keys and its links' credentials in a real node's snapshot.
//
// `diag -o FILE` ([WriteDiagnosticsFile]) writes a new file beside the
// path, mode 0600, synced, and renames it over the path, replacing only a
// regular file: anything else there is refused, a device such as
// /dev/null, a directory, and any symlink whatever it points to
// (/dev/stdout is a link through /proc/self/fd/1 to whatever stdout is,
// a file included), so root writing into a directory others can write to
// never follows or replaces their link. `-o -` prints it.
//
// # JSON
//
// What the CLI prints for a script, `status -json` ([WriteStatusJSON])
// and `diag` ([WriteDiagnostics]), follows one convention, opt-in with
// `-json` (`diag` has no text form yet); a person's output stays text.
// TP-181 gives the other commands `-json` in it, and every field added
// to the status (TP-048's kill switch, allow-LAN and pause toggles, say)
// follows it:
//
//   - the schema's own field names, snake_case (`space_id`,
//     `schema_version`), so the JSON says what the local API's message
//     says: a tray reading the API and a script reading the CLI see the
//     same names;
//   - every field present: an unset one as its zero value (`false`, `0`,
//     `""`, `[]`, `{}`) or, a message's, `null` (`data_plane` while the
//     data plane is down, `uplink` on a device, a peer's `last_handshake`
//     before the first);
//   - a top-level `schema_version`, [SchemaVersion], the one number for
//     every document. `status -json` writes the CLI's own version (the
//     JSON has the fields its schema knows, whatever the service's); the
//     status inside `diag` has the service's;
//   - an enum value in lower snake_case without its type's prefix, as the
//     text view spells it: `connected`, `device`, `ok`, not protojson's
//     `CONNECTION_CONNECTED`, `MODE_DEVICE`, `HEALTH_LEVEL_OK`; the zero
//     value is `unspecified`. Every enum field the schema has is spelled
//     so, nested, in a list or as a map's value, so a new enum follows it
//     with no code. Health problems and other codes are snake_case
//     strings too;
//   - otherwise protojson's spelling of values: a 64-bit integer as a
//     string (`"map_version": "1793188210"`), a timestamp as
//     RFC 3339 in UTC, a duration as seconds (`"1.5s"`);
//   - one object, indented by two spaces, then a newline, the same bytes
//     for the same state (protojson's own whitespace is randomized per
//     build, so it is re-indented); `status -json -watch` writes one
//     object after another.
//
// The v1 contract is the field names, their types and their meaning in
// Status and Diagnostics. [SchemaVersion] is bumped when a field is
// removed or renamed or its type or meaning changes, not when one is
// added (a reader ignores fields it doesn't know); `unreadable` texts and
// other free text are not part of it, and enumerated values (an enum, a
// health problem, a route's type, an Apply's step) may grow without a
// bump. Counters' names (`data_plane.counters`) may come and go: a reader
// takes a missing one as 0. Version 2 spelled the enum values as above;
// version 1 had protojson's full names, in diag's status.
//
// # What it reports
//
// Nothing the API reports is a public address, a key or a secret (PRD
// S1, S4), but Diagnose's host parts, root's only, which name public
// addresses (never a key or a secret). Elsewhere nodes and spaces are
// opaque ids, addresses are the overlay's, links name their endpoint by
// its index, and a server's listeners are shown without their addresses.
// Failures are named from fixed
// vocabularies: refusals are [Error] values (go-kernel ddd.DomainError
// values that grpckit's interceptor sends by their code), and a failed
// Connect names only its step (`start_failed:<step>`), the detail going to
// the node's log. A worker's last exit is shown as the supervisor recorded
// it, sanitized. Strings that come from the map or a transport are
// sanitized before they leave ([agent.Sanitize]), and clients sanitize
// every string they receive before showing it ([Client]): worker output
// and anything else from the service is never trusted with a terminal.
package localapi
