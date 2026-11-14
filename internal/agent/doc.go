// Package agent is the node agent, on servers and devices alike: it
// follows its space's maps and applies each, runs the data plane, and
// hands `thinkpol up` what runs the node next to the local API (package
// localapi). Server-only parts live in agent/supervisor and agent/worker;
// installing it as the host's service is agent/service's. Not yet:
// updating itself (TP-044).
//
// # Engine and agent
//
// The engine ([dataplane.Engine]) is in-process wiring configured by one
// Apply per map, and owns the ports it drives (package dataplane says
// which, and why it imports none of the host adapters). Everything around
// it is the agent's: watching for maps and applying each, building the
// transport registry ([Transports], whose sockets carry the host's
// marking), opening, serving and closing the listeners, and adapting
// netcfg, routetable and dns to the engine's ports, adding what only an
// adapter means, such as the resolver's direct upstreams, which the route
// table keeps reachable.
//
// The node's host adapters are chosen and wired per OS by the composition
// root (cmd/thinkpol) and handed over as a [Platform]. Its [Host] is what
// one data plane needs, in two parts: a [WorkerHost], what any data plane
// needs of its network namespace (a configurator per owner, the TUN, the
// transport registry, the blob services' network), and a [DeviceHost],
// what only a device's uses, which a server's worker never gets: the
// route table with the host's leak guard (package firewall's adapter for
// routetable's Guard port; routetable never imports firewall), clearing
// what a crashed run left, and the OS's resolvers and their
// configuration. The Platform adds what is host-wide: the host's agent
// lock and putting back a resolver configuration a crashed run left. Some
// of them are this package's own functions ([HostLock], [Transports]).
// The agent only sequences them.
//
// [Prepare] reads and checks what the node runs from, touching nothing on
// the host; [Node.Adapters] then returns the node's adapters (the map
// watcher and the node), which `thinkpol up` runs with the local API's
// under go-kernel's app.RunWith.
//
// # Configuration and logs
//
// `thinkpol up` uses go-kernel's config, app and observability (and the
// local API, grpckit and ddd). Its environment variables (THINKPOL_*) and
// flags come from one tagged struct, [Config]: [LoadConfig] reads the
// environment and the defaults and no .env files, [ApplyOSDefaults] fills
// the defaults that vary by OS (which a tag can't), config.BindFlags makes
// the flags from the same tags, [ApplyNodeFile] then takes what the node
// file sets and neither a flag nor a variable did, and the result is
// validated once ([Config.Validate]). For each setting the first source
// that sets it wins: a flag, the environment (a variable set, even empty),
// the node file, the default (docs/design/configuration.md "Precedence and
// narrowing"). app.RunWith runs the adapters with the agent's logger; a
// first SIGINT or SIGTERM shuts the node down, a second one force-quits a
// hung shutdown.
//
// The node file ([NodeFile], node.json in the state directory) is the
// operator's settings: one JSON object, root's, 0600, written by hand or
// by provisioning, never by the agent ([ReadNodeFile]). Its keys, each
// optional, are the flags' settings in snake_case:
//
//	mode            "device" (the default) or "server" (-mode)
//	interface       the TUN's name (-interface)
//	link_mtu        the MTU under the links, 576 to 65535; 0: 1500 (-link-mtu)
//	log_level       "debug", "info", "warn" or "error" (-log-level)
//	map_poll        how often to check the map file, a duration like "5s" (-map-poll)
//	dns             whether a device runs its resolver, true or false (-dns)
//	dns_upstream    a list of resolvers, each "IP" or "IP:port" (-dns-upstream)
//	egress_allowed  a list of private prefixes an exit's spaces may reach (-egress-allowed)
//	kill_switch     a device's kill switch until a member sets it, true or false (-kill-switch)
//	allow_lan       whether the kill switch lets the LAN out, until a member sets it (-allow-lan)
//	fail_closed_after_crash  the crash posture, true (the default) or false to opt out (-fail-closed-after-crash)
//
// What says where the node's files are (-state, -map, -api-socket,
// -api-group) or how it is run (-service, -connect) is not in it. The file
// is strict ([decodeSettings], shared with [DeviceFile]): keys match
// exactly (encoding/json alone ignores case), a key given twice, an
// unknown key, a value of the wrong type or a bad value, invalid JSON and
// an empty file (`{}` is a file without settings) each stop `up` with a
// [*ConfigError] naming the file and the key or the value, which the CLI
// exits with as EX_CONFIG (78). A bad value is refused even when a flag or
// a variable overrides it: the file is the operator's, and a mistake in it
// is never passed over. So is a null (leave the key out for the default),
// and a file that isn't the service's user's (root's) or that others may
// read: 0600 is enforced, the message saying what to chmod or chown. None
// is fine: every setting has its default. It is read once, at start: a
// change takes effect at the next start.
//
// `up` refuses to start, with a [*ConfigError], while
// THINKPOL_CONNECT_ON_BOOT is in its environment ([CheckEnvironment]): only
// a service definition older than the binary sets it, and such a
// definition, run without -service, would connect at every start. A
// variable that doesn't parse (THINKPOL_LINK_MTU=abc) is a *ConfigError
// too, as is a device that would start disconnected without the local API.
//
// The agent's log ([NewLogs]) is observability's text logger, writing to
// stderr and to an in-memory [logring.Ring] of [LogRingSize], at the
// node's own level ([Config.LogLevel]: -log-level, THINKPOL_LOG_LEVEL),
// never go-kernel's LOG_LEVEL. grpc's own log joins it
// (localapi.RouteGRPCLog) instead of going to stderr. The agent writes it
// to no file (PRD S2): under a device's service stderr is the crash trace
// and the log goes only to the ring ([CrashTrace.LogOutput]), as it does
// under `up -service` whenever stderr is any other regular file. Under
// systemd a server's stderr is the journal, which keeps the log on disk
// unless the journal is volatile: nothing sets that yet (provisioning
// will, TP-038; RESIDUAL-RISKS.md RR40). The local API serves the ring to
// root only, since debug lines may quote the map.
//
// A device's crash trace is PRD S2's one exception: under a device's
// service, stderr is [CrashTraceFile] in the state directory, which the
// service manager opens for each run, appending (package service, "The
// definitions"). `up` first thing, before anything of the run writes to
// stderr, makes the file root's and 0600 whatever the manager created it
// with (service install creates it so; a wider one is fixed and said in
// the log), and reads what the runs before left there ([TakeCrashTrace]:
// the head, up to [CrashTraceLimit], as valid UTF-8, cut at a character),
// cutting the file to that head. The node empties it only once it has the
// trace ([Node.KeepLastRun], [CrashTrace.Release]): a start that fails
// before that adds its error after the trace, and the next start reads
// both, so a crash followed by failing starts isn't lost; the file stays
// bounded by its head and one run's output. A file with another link isn't
// read: it is emptied and removed, and the run's stderr goes to the null
// device ([CrashTrace.Detach]); so does it, without writing to the file,
// when the file can't be fixed, cut or emptied, which stops the start.
// The agent's log goes only to the ring, so the file holds what the
// runtime writes there (a panic's trace, a fatal error's, SIGQUIT's
// goroutine dump) and the error `up` exits with: nothing on a clean stop
// (a signal's cancellation is no error, [CleanStop]), and nothing from a
// kill. Status says the last run crashed (Status.LastRunCrashed), or that
// its trace wasn't read (Status.LastRunUnreadable), and Diagnostics has
// the trace, or why, root's only. A server keeps no trace: right after
// reading the file, before anything else that can fail, `up` detaches
// stderr from it (emptied, removed, stderr to the null device) unless the
// node is known to be a device: its node file says "device" (whatever
// its map), or sets no mode and its map shows the node as a device
// ([CrashTrace.KeepOnlyOnADevice]). A device mode given only by a flag or
// the environment isn't enough (the default can't be told from one
// given: a device that wants one set node.json's "mode"), and a node the
// map makes a server or doesn't hold, or whose state directory or node
// file can't be read, keeps none, even of the start's own error. A
// server's start detaches the same way once the node is prepared
// ([Node.KeepLastRun]), warning that a device's definition runs it, and
// warns of a crash-trace it finds in its state directory otherwise. A
// device that detaches (a file it couldn't empty) makes the file anew,
// root's 0600, so its manager's next start doesn't create it with its
// own mode. grpc's fatal errors are written to stderr
// as well as the log, so the trace says why the agent exited.
// A stderr that isn't the file (a terminal, the journal, a server's
// service) leaves it alone, and the log goes to stderr as ever. It survives a
// reboot, unlike the runtime directory (/run on Linux), so a crash just
// before one is still there, and the manager can open it before the agent
// has made any directory of its own. A server's workers log at the
// node's level; only the node owner's space's worker output joins the
// node's log, line by line, prefixed with its space and sanitized
// ([Sanitize]), while a guest space's stays in its own ring in the
// supervisor.
//
// # One agent per host
//
// A node agent changes host-wide state outside any namespace (routes, the
// resolver configuration), so one runs per host. Before [Node.Adapters]
// hands anything over, before anything of the node or its local API
// touches the host, it takes the host's agent lock ([HostLock]): an
// exclusive flock on /run/thinkpol/agent.lock on Linux and
// /private/var/db/thinkpol/agent.lock on macOS, next to netcfg's locks,
// close-on-exec so no worker inherits it, and released when the node
// stops or the process dies. Its directory is opened through
// [trusteddir], so no one can rename it away from under a running agent
// and have the next one lock a fresh file (trusteddir says why every
// directory on the way counts, and why that rules out macOS's /var/run).
//
// A second `thinkpol up` exits with "another thinkpol agent is running on
// this host" and changes nothing. Its start-time cleanups (putting back a
// resolver configuration a crash left, clearing a crashed run's route
// table and overlay routes) would otherwise undo the running agent's.
//
// # Device and server
//
// Device mode ([ModeDevice]) runs one space's engine in-process on the
// node's own TUN and sockets ([RunDataPlane]). Server mode ([ModeServer])
// runs the supervisor and a worker per space, each running the same data
// plane with the supervisor's shared listeners as its inbound; it needs
// Linux, and on macOS the node refuses to start in it.
//
// The mode is the node's own, never its kind in the map (PRD A4: a node
// starts with ingress and egress off): -mode, THINKPOL_MODE or the node
// file's "mode", in that order, and device when none sets it. A server
// sets "mode": "server" in its node file (or runs with -mode server); a
// value other than device or server, the gone "auto" among them, exits
// EX_CONFIG. A node that starts removed from its space runs in its mode
// all the same, and a newer map that changes its kind changes nothing of
// the mode.
//
// Device mode runs no server's section (kind server, an entry or an exit
// alike): it would open the map's public listeners, admit links and relay
// other nodes' packets. A node in device mode whose map makes it a server
// (a server whose node file lost its mode, say after an upgrade from when
// the map's kind picked it) is handled like a removed one: no listener,
// link, relay or egress, and the host's network left alone (no TUN,
// route, resolver configuration or firewall, not even a crashed run's
// clean-up: the box is a server's). The agent stays up following the
// space's maps, the local API answers, Status has ModeMismatch (health
// problem mode_mismatch), and the log says to set "mode": "server" in
// node.json (or -mode server) and restart. A newer map that makes a
// running device a server stops its data plane the same way; one that
// makes it a device again starts it.
//
// Failing closed costs this: a device that crashed while connected and
// comes back on a map that makes it a server keeps what the crashed run
// left (its resolver configuration, the route table's rules, its kill
// switch) until a map makes it a device again, or `thinkpol rollback`
// ([Rollback]) or `thinkpol service uninstall` clears the host
// ([Platform.ClearHost]) while no agent runs; `thinkpol
// disconnect` and `thinkpol kill-switch off` in that state clear none of
// it, and report success: the toggle is stored and the connection down,
// as asked, but the host is left alone. A mismatch is told to no subscriber: no event says it
// starts or ends (nothing subscribes in production yet), only Status and
// the log.
//
// Planned (TP-183): the node's own configuration as a ceiling over what
// the map asks of it (docs/design/overlay.md "Node agent"). Until it
// exists, a signed map alone decides the role of a node run in server
// mode (RESIDUAL-RISKS.md RR42). The ceiling is a preset, device or
// server, and within server each capability on its own: ingress (public
// listeners), egress (forwarding to the internet, with EgressAllowed) and
// relaying; later, serving guest spaces and their caps. A fresh install
// is a device; anything more is opted into locally (provisioning does it
// with the operator's consent, TP-038). To a node, a map is two things:
// what the others are (peers, keys, revocations, routes), which it always
// takes from a newer signed map, and what this node is asked to do. At
// start, a map that asks this node for more than its ceiling leaves it
// down: health says why, and it carries no traffic. While running, it
// keeps its last accepted capabilities, takes the rest of the newer map,
// and reports the refusal in health and in the log; it saves only what it
// accepted, so a restart comes back to that. The same holds when the
// owner lowers the ceiling under a running map. With the controller (M4),
// nodes advertise their ceiling and the builder refuses to publish a map
// that asks for more; each node still enforces it.
//
// # Taking a new map
//
// The map watcher checks the map file every -map-poll (5 s by default)
// for a change (replaced, resized or touched), and reads it at once on
// SIGHUP; what it reads goes to the node latest-wins. The node takes it
// only through [netmap.Map.Next]: valid, signed by the space and newer
// than the map it has; otherwise it keeps running on the current one.
// Device mode, server mode and a node waiting while removed all take maps
// through the same follower, so what a newer map means can't drift
// between them. The map is all a node takes: it never asks a controller.
//
// A valid newer map without a section for the node means it was removed
// from the space. The data plane stops (on a server, the space's worker
// and listeners), the agent stays up and idle following the space's maps,
// and the data plane starts again when a later map includes the node. A
// node that finds itself removed when it starts (its map, valid, has no
// section for it) starts the same way, idle, rather than failing and being
// restarted over and over by its service manager.
//
// # A device's connection
//
// A device's connection is one state with its transitions (connection):
// disconnected (down on purpose, still following the space's maps),
// connecting, connected, removed (meant to be up while its map has no
// section for the node) and retrying (meant to be up, but a start failed:
// it starts again after [RetryAfter], on a newer map, or on a Connect). A
// move its state can't make is refused, logged as a bug, and leaves it
// where it was. [Status] shows it as [Disconnected], [Connecting] (which
// covers removed and retrying), [Connected], or [Serving] on a server.
//
// [Node.Connect] and [Node.Disconnect] (the local API's) bring a device's
// data plane up and down while the service keeps running and following its
// space's maps. Connect starts it at once on the current map and returns
// once it is up, or with the step it failed at (a [*StartError]); out of
// its space, it comes up once a map includes the node again. -connect=false
// (THINKPOL_CONNECT) starts a device disconnected, which then needs the
// local API to connect. A server serves its spaces whenever it runs and
// refuses both ([ErrServerMode]). A device whose node returned (stopped,
// or its first start failed) reads disconnected.
//
// The service runs `up -service` ([Config.Service], THINKPOL_SERVICE).
// Connect-on-boot is the member's toggle in the device file ([DeviceFile]),
// set through the local API ([Node.SetConnectOnBoot]; PRD D5: off unless
// the member turns it on); it takes effect at the next boot. Under the
// service a device keeps its connect choice for the boot ([ConnectRecord]: [ConnectRecordFile]
// next to the host's agent lock, stamped with the boot session): the
// first start of a boot (no record, or one of an earlier boot) connects
// if connect-on-boot is on and records that; each Connect and Disconnect
// is recorded before it is acted on, and a Connect that fails, leaving the
// device down, records it down again; `thinkpol rollback` records it
// down too ([Rollback]). A later start in the same boot follows the
// record: a crash and the service's restart neither drop a connected
// member (whose traffic would go direct) nor undo their disconnect or
// rollback, whatever connect-on-boot says by then. A start reads the
// record under the host's agent lock ([Node.Adapters]), which rollback
// writes it under: a start whose process began while a rollback ran
// either is refused the lock or reads the rollback's record. -service needs the
// local API, without which nothing could change the choice (Validate
// refuses it). Run by hand, without it, -connect decides every start and
// nothing is recorded. A record that can't be written is logged and the
// node goes ahead; one that can't be read is logged and connect-on-boot
// decides.
//
// A rule preset chosen through the local API ([Node.SetRulePreset]) is
// taken by the goroutine that runs the data plane: it stores the preset
// in [DeviceFile], hands it to the engine ([dataplane.Engine.SetRules])
// at once, and only then has Status show it. With no data plane running
// (the node waits for a section, or stopped) it is stored and shown, and
// the next start takes it: every start takes the stored preset as
// [dataplane.EngineConfig.Rules]. A request the node never took (its
// caller gave up first) changes nothing, and a store that fails leaves
// the old preset everywhere. Status says the preset is enforced
// (RulesEnforced) only while the engine's router enforces that preset
// ([dataplane.RuleStatus.Preset]). When laying it out fails, the router
// keeps the previous preset: the stored one is shown as not enforced yet
// ([ProblemPresetNotEnforced]), the caller gets [ErrPresetNotEnforced],
// and the data plane hands it over again at its retry, after applying the
// section, until it is laid out.
//
// The device file ([DeviceFile], device.json in the state directory) is
// the member's toggles ([DeviceSettings]), as strict as the node file, 0600:
//
//	connect_on_boot  true or false: the service connects at a boot's first start
//	rule_preset      "space", "everything" or "all-but-domestic"
//	rules            the device's own rules, ahead of the preset's, each "match -> action"
//	kill_switch      true or false: the kill switch (below); once a member set it
//	allow_lan        true or false: whether the kill switch lets the LAN out; once set
//
// Only the service writes it, atomically, every key (the kill switch's
// once a member set them: until then the node's defaults hold), when a
// member of the API group changes a toggle; a key left out is its
// default. A device kept
// its rules in rules.local ([LocalRulesFile]) before: the first start that
// finds one (under the host lock, [Node.Adapters]) writes its preset and
// own rules into the device file, removes rules.local and logs it; a
// directory holding both (a start stopped between the two) keeps the
// device file and only removes rules.local.
//
// # The kill switch
//
// A device's kill switch ([KillSwitch], the host's: package firewall) is
// kept by the goroutine that runs the node, never by the route table: it
// outlives a disconnect, a stop and a crash. It is in place when the
// toggle is on (the device file's kill_switch, else the node's), and,
// the toggle off, under the "everything" and "all but domestic" presets
// while the connection is meant up (connecting, connected, retrying,
// removed), unless the node file opts out (fail_closed_after_crash): the
// crash posture, so a crash leaves it. Otherwise it is removed. Its rules
// ([firewall.KillSwitchRules]) are the down shape (the endpoints of the
// links in the device's section, none while removed, and with allow-LAN
// the LAN, but DNS to it: NoDNS, the LAN, an entry on it included (on
// Linux the links' sockets pass by their mark before the refusals; on
// macOS an entry whose transport is on port 53 or 853 is spared), as
// the OS is back on its own resolvers, a router that forwards lookups in
// the clear; owner, 2026-11-12) or, while the data plane is up, the connected
// one: the TUN, and the direct destinations and upstreams the route
// table exempts (routetable.GuardFor of the last Want) on top, and with
// allow-LAN the whole LAN, DNS included.
//
// When: at start, before connecting and before the resolver configuration
// a crash left is put back (a crashed or stopped run's rules are narrowed
// to the down shape, or removed if not meant); at every turn of the
// node's loop (a connect, a disconnect, a map, a preset, a retry); at
// every 10 s tick (a re-apply checks it is whole, and on Linux renews the
// direct destinations, which expire 30 s after the last one; an apply
// between ticks can push the next re-apply a tick later, so they are
// renewed, and a change from outside repaired, at most about 15 s apart,
// and a node loop stalled for about 15 s lets them expire); and when a
// member changes a toggle ([Node.SetKillSwitch], [Node.SetAllowLAN]),
// which return once it was acted on. A stop is no deliberate disconnect:
// the node returning leaves the down shape in place if it was meant up or
// the toggle is on, as a crash would, and warns so ([KillSwitchStopNote])
// whenever rules are in place, an apply that put them there but failed
// ([firewall.ErrKillSwitchInPlace]) included.
// Only a deliberate disconnect with the toggle off (or no crash posture),
// a start that comes up so, `rollback` ([Rollback]) or `service
// uninstall` ([Platform.ClearHost]) removes it. A disconnect is recorded for the boot before the node hears
// of it ([Node.Disconnect]), so one sent while a slow first start hangs,
// and waited on until it fails, is honoured by the next start; one whose
// caller gives up while the node runs puts the node's own choice back. A
// start that fails at once serves the local API for milliseconds, so
// there the way out is `sudo thinkpol rollback` ([Rollback]: under the
// host lock, the boot's connect choice recorded down, so the service's
// next start comes up disconnected, then the agent's start-time cleanup,
// the kill switch with it; the member choosing no tunnel over failing
// closed) or `service uninstall`. A mode mismatch leaves a previous run's kill switch alone
// (above); until the node applies it, the status says it isn't applied
// yet (`not_applied`, which the health leaves to the start). A failure is
// logged, retried at the next turn or within 10 s, and in the status
// ([KillSwitchStatus], health `kill_switch_not_enforced`, or
// `kill_switch_unsupported` where the OS can't hold it); it never fails a
// connect. A server has none, and removes at its start what a device run
// on the host left: it would refuse the server's traffic.
//
// # Events
//
// What happens to a node is told as typed events ([Event]) to whoever
// subscribes ([Node.Subscribe]), each once the node's status shows it, on
// the goroutine that runs the node: removed from the space and back in it,
// connected, DNS unprotected (`dns_not_protected`), and the route table not
// enforced (whether an Apply or a rule change failed to put the rules in
// place or the route table failed to put them back on its own). Each is an
// edge: a problem is told when the status starts showing it, not on every
// retry that fails again, and again only once the status said otherwise or
// the data plane went down.
//
// # The state directory
//
// Of its own, a node keeps its state directory ([DefaultStateDir]:
// /var/lib/thinkpol, /private/var/lib/thinkpol on macOS; -state) on disk,
// and on macOS the records listed under "Outside the state directory"
// (PRD S1). [LoadState] reads it:
//
//   - node.key ([NodeKeyFile]): the node's id and private keys, 0600,
//     written once, on the node, when it is provisioned;
//   - space.pub ([TrustFile]): the space's id and public keys, what every
//     map is verified against;
//   - map.bin ([MapFileName]): the newest map of the space, of which the
//     node can open only its own section. `thinkpol up` reads and watches
//     it and won't start without a valid one; whoever provisions or
//     updates the node puts it there (-map names another file). Not yet:
//     the node replacing it atomically whenever it takes a newer map from
//     the network (TP-037);
//   - node.json ([NodeFile]), if the operator wrote one: the node's
//     settings (above), never written by the agent;
//   - device.json ([DeviceFile]), once a member set a toggle: the
//     member's toggles, written atomically by the service when the local
//     API changes them, and by nothing else;
//   - blobs/ ([BlobDir]): files named by their SHA-256.
//
// A server only reads blobs/: the seeds of its space's lists that
// provisioning put there, which the supervisor reads when it sends them to
// a worker (one sealed memfd each, kept nowhere else). What a worker
// fetches from peers stays in its memory, since a server uses no list
// itself and fetches the set again after a restart. A device keeps there
// the lists its rules use, with an index of their names, fetched from
// peers and pruned when the map stops naming them, because it needs them
// from the moment it starts, before any peer is reachable; the previous
// version of a list stays until its successor is verified. Either way the
// contents are public lists the map already names by hash, checked against
// the map whenever they are read.
//
// The directory and its files (and the map's directory, when -map names
// another) belong to the node's user (or root), are writable by no one
// else and are never symlinks, and so is every directory on the way from /
// ([trusteddir]): whoever could replace space.pub would choose the maps
// the node trusts, and whoever could replace map.bin could put back an
// older signed map for the node's next start (a running node refuses
// anything older than what it has; a starting one has only the file). A
// space's private key found there (space.key, recovery.key) stops the node;
// anything else unexpected is reported and not used. A device file (or a
// rules.local still to carry over) that can't be read or parsed stops the
// node from starting rather than reading as no settings.
//
// `thinkpol up` writes nothing else there (a device's blobs/ aside). A
// server's workers get their keys and map from the supervisor over their
// sockets, since they can't read the directory. The agent writes no pid
// or log file.
//
// # Outside the state directory
//
// What else a node changes on the host, each owned so that a crashed run's
// is found and undone or taken over at the next start:
//
//   - Locks, recorded nowhere else: the agent's lock (above), netcfg's
//     owner locks and the local API's lock next to its socket. On Linux
//     they are under /run (/run/thinkpol, /run/thinkpol-api), a tmpfs; on
//     macOS, which has none, under /private/var/db (thinkpol,
//     thinkpol-api), on disk.
//   - Under the service (-service), a device's connect choice for
//     the boot ([ConnectRecordFile], above), next to the agent's lock,
//     stamped with the boot session; `thinkpol rollback` writes it too.
//   - On macOS, records under /private/var/db/thinkpol: netcfg's route
//     records (netcfg/<owner>.routes, next to <owner>.lock), which list
//     the routes it added, the link endpoints' addresses among them, and
//     the leak guard's and the kill switch's pf enable references
//     (pf-guard.token, pf-killswitch.token). They outlive
//     a crash on purpose, and are stamped with the boot session, so a
//     record of an earlier boot owns nothing. A corrupt route record is
//     set aside by its owner at start, as <owner>.routes.corrupt-<boot
//     session>, and removed at its first start in a later boot; another
//     owner's is reported in place, never touched (its owner sets it
//     aside at its next start or, still running, rewrites it at its next
//     change). Health `route_records_corrupt` while a corrupt record is
//     seen and routes no record names are left.
//   - Routes and policy rules (package routetable and netcfg), and the
//     leak guard: an nftables table on Linux; a pf anchor and an enable
//     reference on macOS (package firewall).
//   - A device's kill switch: an nftables table on Linux; a pf anchor and
//     an enable reference (its record pf-killswitch.token, next to the
//     guard's) on macOS (package firewall). It outlives a crash and a
//     stop on purpose (above).
//   - The OS's resolver configuration (package dns): on Linux
//     systemd-resolved's link for the TUN, or /etc/resolv.conf rewritten
//     with the overlay resolver's addresses and the space's zone, the
//     original kept inside the file and put back when the device
//     disconnects or stops; on macOS overrides in configd's in-memory
//     store, the originals kept there.
//   - On a server, the supervisor's nftables tables and the forwarding it
//     turned on, recorded in /run/thinkpol (package supervisor).
package agent
