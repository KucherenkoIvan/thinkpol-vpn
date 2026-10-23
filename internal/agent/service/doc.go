// Package service installs the node agent as the host's service (PRD D2,
// D5): a systemd unit on Linux, a launchd daemon on macOS (`thinkpol
// service install`, `uninstall`, `connect-on-boot`). The Windows service
// is TP-047's. It changes the host only through the [Installer]'s paths
// and its service manager's tools ([System]: [Systemd], [Launchd]), so
// tests run it against a temporary root and a fake manager.
//
// # What install does
//
// As root, and only once the host runs the manager (systemd: there is a
// /run/systemd/system; OpenRC, a container or WSL1 is refused before
// anything changes) and the node can run (its state directory reads as
// `thinkpol up` would read it: without keys and a map the service would
// only restart). Every step that can fail runs before anything is
// stopped, so a failed reinstall leaves a working service running and
// enabled. With no service installed, install refuses while an agent
// holds the host lock (one run by hand, which the service's agent would
// only restart against, every RestartAfterSeconds, forever); with one,
// whose agent holds the lock itself, the check comes after the service
// is stopped (systemctl stop, still enabled; launchd's bootout) and before
// it is started again. It:
//
//   - copies the running binary to [BinaryPath], /usr/local/bin/thinkpol,
//     which the service runs as root. Its directory, and every one above
//     it, must be root's and writable by no one else (trusteddir), or
//     install refuses: whoever could replace the binary would run as root
//     (a /usr/local/bin a package manager gave a user, say). What is at
//     BinaryPath is kept only if it is root's own regular file, 0755, and
//     the running binary itself; a symlink, or a file anyone else could
//     change, is replaced with a copy;
//   - makes the local API's group, [Group] (`thinkpol`, the agent's
//     default -api-group), if it is missing (groupadd -r; dseditgroup in
//     Directory Services on macOS), and adds the user who ran sudo
//     (SUDO_USER; -user names another, empty no one) unless they are in
//     it. A member gets the group from their next login
//     (RESIDUAL-RISKS.md RR43 for macOS);
//   - writes the definition ([SystemdUnit] at [UnitPath], [LaunchdPlist]
//     at [PlistPath]), 0644, replaced atomically: the manager reads it
//     only when started below;
//   - stops an installed service, checks the host lock, and (re)starts
//     it: `systemctl daemon-reload`, `enable` and `restart`; `launchctl
//     bootstrap`, retried briefly when launchd refuses it with EIO just
//     after the job it replaces is gone. `launchctl enable` runs only if
//     someone disabled the daemon, so a clean install writes no launchd
//     override.
//
// Stopping a launchd daemon is `launchctl bootout`, then a wait until
// `launchctl print` no longer shows it, whatever bootout said: it may
// return before the agent has exited, or fail with a slow exit
// ("Operation now in progress") that ends all the same. The wait lasts up
// to [StopTimeoutSeconds] and a margin; bootout's error is reported only
// if the daemon outlives it. A print that fails for another reason than
// no such service (exit status 113) fails the stop rather than read as
// gone, so nothing is removed from under a daemon launchd still has.
//
// Installing again replaces the binary and restarts the agent, keeping
// connect-on-boot unless -connect-on-boot on|off says otherwise. The
// agent comes back as the member left it, since a start in the same boot
// follows the boot's recorded connect choice (package agent, "A device's
// connection"). A definition that isn't what install writes (edited by
// hand, or unreadable) is replaced with a warning, connect-on-boot off
// unless -connect-on-boot says otherwise.
//
// # The definitions
//
// Both run `thinkpol up` with the node's defaults and one setting,
// THINKPOL_CONNECT_ON_BOOT: off unless the member turns it on (PRD D5).
// Set, it also has a device keep its connect choice for the boot, so a
// start in the same boot (after a crash, a restart) comes back as the
// device was left, whatever connect-on-boot says (package agent, "A
// device's connection"). Both restart the agent whenever it exits, after
// [RestartAfterSeconds] seconds, without a limit (crash posture:
// docs/design/security.md "Kill switch"): systemd's Restart=always with
// StartLimitIntervalSec=0; launchd's KeepAlive with ThrottleInterval. A
// stop waits [StopTimeoutSeconds] for the agent to take its data plane
// down (TimeoutStopSec, ExitTimeOut).
//
// The systemd unit:
//
//   - has no RuntimeDirectory=: systemd would delete /run/thinkpol when the
//     unit stops, and with it the inode of the agent's host lock, so a
//     second agent could lock a fresh file while the first still runs
//     (package agent, "One agent per host"). The agent makes /run/thinkpol
//     and /run/thinkpol-api itself (root 0700; the API's 0750 with the
//     group);
//   - uses KillMode=mixed: SIGTERM goes to the agent alone, which stops a
//     server's workers itself; whatever is left is killed after it;
//   - reloads with SIGHUP to the agent alone (`systemctl reload thinkpol`),
//     which reads the map file at once; a server's workers don't handle
//     SIGHUP. Under launchd: `launchctl kill HUP system/org.thinkpol.agent`;
//   - starts after network.target and systemd-resolved (if there), and
//     so stops before them, with the network still there to undo its
//     routes and resolver configuration against.
//
// The launchd daemon sets no StandardOutPath or StandardErrorPath, so
// the agent's stderr goes nowhere on disk (PRD S2); its log is the local
// API's. Under systemd stderr is the journal (RESIDUAL-RISKS.md RR40).
//
// # Connect-on-boot
//
// `thinkpol service connect-on-boot on|off` rewrites the definition with
// the other THINKPOL_CONNECT_ON_BOOT and has the manager take it at the
// next start (systemd's daemon-reload; launchd reads the plist when it
// boots), without restarting the agent: only a boot's first start reads
// it. Without an argument it prints the setting. No definition is
// [ErrNotInstalled]; one that isn't exactly what install writes (edited by
// hand) is [ErrDefinitionChanged]: install again.
//
// # What uninstall leaves
//
// Nothing of the service but its group. It stops the service, disabled
// (systemctl disable --now; launchd's bootout), and waits for the agent to
// exit (which takes its data plane down: TUN, routes, leak guard, the
// resolver configuration), then takes the host's agent lock: while an
// agent still holds it (one run by hand, one the stop didn't end)
// uninstall refuses before it touches a lock or a record, since removing
// them would let the next agent lock a fresh inode beside the running one.
// Holding the lock, it undoes what a crashed device agent left (the
// agent's start-time cleanup without a connect: the route table's routes
// and leak guard, the overlay's routes, the resolver configuration, a
// missing resolv.conf being nothing to put back; a stop that timed out
// leaves them too), and only then removes the definition (systemd forgets
// the unit), the binary, and in the agent's runtime directories (its
// lock's directory, the local API's) the locks, the boot's connect record
// and stale sockets, then the directories left empty. It removes
// agent.lock while it holds it: the service can't start an agent in
// between (systemd's is disabled and stopped, launchd's booted out), and
// one started by hand afterwards makes a fresh lock with nothing to share.
// Anything else there is reported and left: on macOS a crashed run's route
// or pf records; on a server, the supervisor's forwarding.json. A server's
// crash leftovers (the supervisor's nftables tables and the forwarding it
// turned on) stay until a reboot: uninstall runs a device's cleanup only
// (TP-132). The group stays: it may be older than the service, or
// someone's group for other reasons; remove it by hand if nothing uses it.
// So does the node's state directory, its keys and map.
//
// # Where it is proven
//
// The lab runs a device under systemd (lab TestServiceUnderSystemd):
// install, a reinstall over the running connected agent, a crash
// restarted and back as the member left it, connect-on-boot off then on
// across reboots, uninstall right after a crash (the restart held off)
// leaving nothing, before and after a reboot. launchd is tested as files
// and with a fake launchctl here; the install, reboot and uninstall on a
// Mac are the owner's device steps (TP-046's checklist).
package service
