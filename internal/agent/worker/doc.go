// Package worker runs one space's data plane on a server node, inside that
// space's own namespaces, as `thinkpol worker -space <id>` started by the
// supervisor (see package supervisor and docs/design/server-agent.md "Server agent: one worker
// per space").
//
// A worker starts as the root of a fresh user namespace, with fresh
// network, mount, PID, IPC, UTS and cgroup namespaces inside it, and its
// sockets to the supervisor at ipc.ControlFD and ipc.DataFD. It waits for
// the supervisor's Init (its namespace is wired by then), sandboxes itself,
// reports Ready and serves until the supervisor says Stop or goes away.
//
// # Sandbox
//
// Before serving, the worker:
//
//   - checks that it is PID 1 of its own namespace and that its user
//     namespace maps its uid 0 to the host uid the supervisor chose (the
//     slot's unprivileged uid): the escape defence rests on it, since its
//     capabilities then reach only its own namespaces and not the root
//     namespace through the veth's link-netnsid. This is the only thing
//     it reads from /proc, before pivot_root;
//   - pivot_roots into a fresh tmpfs holding only /dev/null, /dev/zero,
//     /dev/urandom and /dev/net/tun (bind-mounted from the host, since
//     mknod isn't allowed in a user namespace) and empty /run and /tmp
//     (tmpfs, nosuid, nodev, noexec), and detaches the old root. Its /run
//     is its own: netcfg keeps its lock files in RunDir (/run/thinkpol),
//     and nothing of the node's /run is visible. No /proc or /sys is
//     mounted: a masked, locked one on a sandboxed host can't be replaced
//     from a child user namespace, and the worker needs neither, since the
//     data plane uses netlink and /dev/net/tun and the supervisor sets the
//     space's network sysctls by entering its namespace;
//   - sets RLIMIT_NPROC to the Init's PidsMax, if any (a fallback where
//     the supervisor's cgroup can't cap its processes);
//   - sets no_new_privs, on every thread of the runtime (it is per
//     thread);
//   - drops SYS_ADMIN (needed only for the mounts) and every capability
//     but NET_ADMIN (its TUN, routes and nftables), NET_RAW (the data
//     plane) and NET_BIND_SERVICE (its DNS resolver on port 53) from the
//     bounding, ambient, inheritable, permitted and effective sets, on
//     every thread;
//   - sets the parent-death signal (SIGKILL) again on every thread, so it
//     never outlives the supervisor;
//   - reads back no_new_privs and its capabilities (through prctl and
//     capget, having no /proc) and that /dev/net/tun is there, and fails
//     rather than serve with a weaker sandbox.
//
// The supervisor's exec has already cleared its supplementary groups.
//
// # Shared listeners
//
// The supervisor owns the node's public listeners. It tells the worker
// which ones serve it (Session.Listeners): a datagram listener is a
// net.PacketConn reading what the supervisor authenticated and forwarded
// over the data socket, whose writes go back out through the public
// socket, to the addresses the supervisor allows; a stream listener
// delivers the connections whose descriptors the supervisor passed over
// the control socket. The transport's listener on top of them
// ([SharedListener.Listen]) decrypts and filters again, as on any other
// listener. Replies are sent to the supervisor blocking, so a full data
// socket holds up only this worker.
package worker
