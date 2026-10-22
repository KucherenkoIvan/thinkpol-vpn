// Package service installs the node agent as the host's service (PRD D2,
// D5): a systemd unit on Linux, a launchd daemon on macOS (`thinkpol
// service install`, `uninstall`, `connect-on-boot`). The Windows service
// is TP-047's. It changes the host only through the [Installer]'s paths
// and its service manager's tools ([System]: [Systemd], [Launchd]), so
// tests run it against a temporary root and a fake manager.
//
// # What install does
//
// As root, and only once the node can run (its state directory reads as
// `thinkpol up` would read it: without keys and a map the service would
// only restart):
//
//   - copies the running binary to [BinaryPath], /usr/local/bin/thinkpol,
//     which the service runs as root. Its directory, and every one above
//     it, must be root's and writable by no one else (trusteddir), or
//     install refuses: whoever could replace the binary would run as root
//     (a /usr/local/bin a package manager gave a user, say);
//   - makes the local API's group, [Group] (`thinkpol`, the agent's
//     default -api-group), if it is missing (groupadd -r; dseditgroup in
//     Directory Services on macOS), and adds the user who ran sudo
//     (SUDO_USER; -user names another, empty no one). A member gets the
//     group from their next login (RESIDUAL-RISKS.md RR43 for macOS);
//   - writes the definition ([SystemdUnit] at [UnitPath], [LaunchdPlist]
//     at [PlistPath]), 0644, replaced atomically, and (re)starts the
//     service: `systemctl enable` and `restart`; `launchctl bootout`,
//     `enable` and `bootstrap` (retried while a daemon just booted out is
//     still going).
//
// Installing again replaces the binary and restarts the agent, keeping
// connect-on-boot unless -connect-on-boot says otherwise. The agent comes
// back as the member left it, since a start in the same boot follows the
// boot's recorded connect choice (package agent, "A device's
// connection").
//
// # The definitions
//
// Both run `thinkpol up` with the node's defaults and one setting,
// THINKPOL_CONNECT, connect-on-boot: false unless the member turns it on
// (PRD D5). Both restart the agent whenever it exits, after
// [RestartAfter] seconds, without a limit (crash posture: DESIGN.md
// "Kill switch"): systemd's Restart=always with StartLimitIntervalSec=0;
// launchd's KeepAlive with ThrottleInterval. A stop waits 60 s for the
// agent to take its data plane down (TimeoutStopSec, ExitTimeOut).
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
// the other THINKPOL_CONNECT and has the manager take it at the next start
// (systemd's daemon-reload; launchd reads the plist when it boots), without
// restarting the agent: only a boot's first start reads it. Without an
// argument it prints the setting. A definition that isn't exactly what
// install writes (edited by hand) is [ErrNotInstalled]: install again.
//
// # What uninstall leaves
//
// Nothing of the service: it stops it (the agent takes its data plane
// down: TUN, routes, leak guard, the resolver configuration), removes the
// definition (systemd forgets the unit), the binary and the group, and
// in the agent's runtime directories (its lock's directory, the local
// API's) the locks, the boot's connect record and stale sockets, then the
// directories left empty. Anything else there (a crashed run's route or
// pf records, on macOS) is reported and left. The node's state directory,
// its keys and map, stays.
//
// # Where it is proven
//
// The lab runs a device under systemd (lab TestServiceUnderSystemd):
// install, a crash restarted and back as the member left it, connect-on-boot
// off then on across reboots, uninstall leaving nothing, before and after a
// reboot. launchd is tested as files and with a fake launchctl here; the
// install, reboot and uninstall on a Mac are the owner's device steps
// (TP-046's checklist).
package service
