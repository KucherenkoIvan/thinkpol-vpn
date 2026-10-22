// Package agent is the node agent, on servers and devices alike: it
// follows its space's maps and applies each, runs the data plane, and
// hands `thinkpol up` what runs the node next to the local API (package
// localapi). Server-only parts live in agent/supervisor and agent/worker.
// Not yet: installing itself as a service (TP-046) and updating itself
// (TP-044).
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
// environment and the defaults and no .env files (a node's configuration
// is its environment and its flags), [ApplyOSDefaults] fills the defaults
// that vary by OS (which a tag can't), config.BindFlags makes the flags
// from the same tags, and the result is validated once, after the flags
// ([Config.Validate]). app.RunWith runs the adapters with the agent's
// logger; a first SIGINT or SIGTERM shuts the node down, a second one
// force-quits a hung shutdown.
//
// The agent's log ([NewLogs]) is observability's text logger, writing to
// stderr and to an in-memory [logring.Ring] of [LogRingSize], at the
// node's own level ([Config.LogLevel]: -log-level, THINKPOL_LOG_LEVEL),
// never go-kernel's LOG_LEVEL. The agent writes it to no file (PRD S2),
// but under systemd stderr is the journal, which keeps it on disk unless
// the journal is volatile: nothing sets that yet (provisioning will,
// TP-038; RESIDUAL-RISKS.md RR40). The local API serves the ring to root
// only, since debug lines may quote the map. A server's workers log at the
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
// The mode is -mode (THINKPOL_MODE): [ModeAuto], the default, picks it by
// the node's kind in its own section of the map (a server runs in server
// mode, anything else in device mode), and device or server overrides
// that either way. A node that starts removed from its space has no kind
// yet: it picks its mode when a map includes it again. A newer map that
// changes the running node's kind is logged; the mode changes only with a
// restart. The map's kind picks how a node runs and -mode overrides it
// either way: a server section that allows egress, run in device mode, is
// no exit (it forwards nothing, and says so in the log), yet its resolver
// serves the space's overlay like an exit's.
//
// Planned (TP-111): the node's own configuration as a ceiling over what
// the map asks of it (DESIGN.md "Server agent: one worker per space").
// Until it exists, a signed map alone decides a node's role
// (RESIDUAL-RISKS.md RR42). The ceiling is a preset, device or server,
// and within server each capability on its own: ingress (public
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
// A device's connect choice for the boot is recorded ([ConnectRecord]:
// [ConnectRecordFile] next to the host's agent lock, stamped with the
// boot session): the first start of a boot (no record, or one of an
// earlier boot) starts as configured and records that, and each Connect
// and Disconnect is recorded before it is acted on. A later start in the
// same boot takes the record over -connect: a crash and its service's
// restart neither drop a connected member (whose traffic would go direct)
// nor undo their disconnect, whatever the configuration says by then, and
// a restart by hand does the same. So -connect is connect-on-boot, which
// the service install sets off (PRD D5). Without a local API nothing can
// ask, so -connect alone decides and nothing is recorded. A record that
// can't be written is logged and the node goes ahead; one that can't be
// read is logged and -connect decides.
//
// A rule preset chosen through the local API ([Node.SetRulePreset]) is
// stored in [LocalRulesFile] in the state directory, then handed to the
// engine ([dataplane.Engine.SetRules]); every start takes it as
// [dataplane.EngineConfig.Rules].
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
//   - rules.local ([LocalRulesFile]), on a device that chose one: its rule
//     preset and its own rules, written atomically by the service when the
//     local API changes them, and by nothing else;
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
// anything else unexpected is reported and not used. A rules.local that
// can't be read or parsed stops the node from starting rather than reading
// as no rules.
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
//   - A device's connect choice for the boot ([ConnectRecordFile],
//     above), next to the agent's lock, stamped with the boot session.
//   - On macOS, records under /private/var/db/thinkpol: netcfg's route
//     records (netcfg/<owner>.routes, next to <owner>.lock), which list
//     the routes it added, the link endpoints' addresses among them, and
//     the leak guard's pf enable reference (pf-guard.token). They outlive
//     a crash on purpose, and are stamped with the boot session, so a
//     record of an earlier boot owns nothing.
//   - Routes and policy rules (package routetable and netcfg), and the
//     leak guard: an nftables table on Linux; a pf anchor and an enable
//     reference on macOS (package firewall).
//   - The OS's resolver configuration (package dns): on Linux
//     systemd-resolved's link for the TUN, or /etc/resolv.conf rewritten
//     with the overlay resolver's addresses and the space's zone, the
//     original kept inside the file and put back when the device
//     disconnects or stops; on macOS overrides in configd's in-memory
//     store, the originals kept there.
//   - On a server, the supervisor's nftables tables and the forwarding it
//     turned on, recorded in /run/thinkpol (package supervisor).
package agent
