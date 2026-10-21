// Package agent is the node agent, on servers and devices alike: it
// follows its space's maps and applies each, runs the data plane, and
// hands `thinkpol up` what runs the node next to the local API (package
// localapi). Server-only parts live in agent/supervisor and agent/worker.
// Not yet: installing itself as a service (TP-046) and updating itself
// (TP-044).
//
// # Engine and agent
//
// The data-plane engine ([dataplane.Engine]) is in-process wiring,
// configured by one [dataplane.Engine.Apply] per map. Everything around it
// is the agent's: watching for maps and applying each, building the
// transport registry ([Transports], whose sockets carry the host's
// marking), and opening, serving and closing the listeners. The engine
// owns the ports it drives ([dataplane.InterfaceConfigurator],
// [dataplane.RouteTable], [dataplane.Resolver]); netcfg, routetable and
// dns know nothing of them, and the agent adapts them, adding what only an
// adapter means, such as the resolver's direct upstreams, which the route
// table keeps reachable.
//
// The node's host adapters are chosen and wired per OS by the composition
// root (cmd/thinkpol) and handed over as a [Platform]. Its [Host] is what
// one data plane needs: the TUN and its configurator, the route table with
// the host's leak guard (package firewall's adapter for routetable's Guard
// port; routetable never imports firewall), the resolver configuration and
// the transport registry. The Platform adds what is host-wide: the host's
// agent lock and putting back a resolver configuration a crashed run left.
// Some of them are this package's own functions ([HostLock],
// [Transports]). The agent only sequences them.
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
// never go-kernel's LOG_LEVEL. It never goes to a file (PRD S2); under
// systemd stderr is the journal, which provisioning makes volatile. The
// local API serves the ring to root only, since debug lines may quote the
// map. A server's workers log at the node's level; only the node owner's
// space's worker output joins the node's log, line by line, prefixed with
// its space and sanitized ([Sanitize]), while a guest space's stays in its
// own ring in the supervisor.
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
// [trusteddir], which needs every directory on the way to be root's (or
// the agent user's) and writable by no one else, so no one can rename the
// lock's directory away from under a running agent and have the next one
// lock a fresh file. That rules out macOS's /var/run (root:daemon 0775,
// not sticky); /private/var/db is root's alone all the way up. The walk
// also refuses symlinks such as macOS's /var, so every macOS default names
// the real path under /private: the state directory and the lock, and the
// local API's socket too.
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
// restart. Not yet: the node's own configuration as a ceiling over what
// the map asks of it (TP-111). Until then the map's kind picks how a node
// runs and -mode overrides it either way: a server section that allows
// egress, run in device mode, is no exit (it forwards nothing, and says so
// in the log), yet its resolver serves the space's overlay like an exit's.
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
// On disk a node keeps its state directory ([DefaultStateDir]:
// /var/lib/thinkpol, /private/var/lib/thinkpol on macOS; -state) and
// nothing else (PRD S1). [LoadState] reads it:
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
// sockets, since they can't read the directory. No pid, lock or log file
// is kept there or anywhere else on disk: the agent's, netcfg's and the
// local API's locks are on /run, a tmpfs (on macOS, which has none, under
// /private/var/db).
//
// Outside it, a connected device points the OS's resolver at its own
// (package dns): on Linux it rewrites /etc/resolv.conf (unless the OS
// resolves through systemd-resolved) with the overlay resolver's addresses
// and the space's zone, keeping the original inside the file and putting
// it back when the device disconnects or stops; on macOS it overrides the
// network services' DNS in configd's in-memory store instead, keeping the
// originals there.
package agent
