// Package netcfg configures the host side of the overlay: interface
// addresses, MTU, link state, routes (in any table, unicast, throw or
// unreachable, or scoped to an interface on macOS) and policy rules, which
// route-table enforcement of routing rules builds on (package routetable).
// [Configurator] is the port (contract in its doc); [New] returns the
// adapter for this OS, one file per OS. There is none on Windows yet
// (TP-047), and Android never has one: its VpnService sets addresses and
// routes.
//
// Every configurator works for an [Owner] (overlay, supervisor, route
// table), one live configurator per owner and network namespace, and
// owns what it adds: it never changes or removes anyone else's routes,
// and a route with the identity of someone else's fails with
// [ErrConflict]. [Clear] removes what a dead configurator of an owner
// left (a crash), by taking the owner's place and closing it with nothing
// applied; [ClearWith] runs what else only that place makes safe to touch
// (the route table's leak guard) before closing it, and nothing at all
// when the place can't be taken, since it may be a live owner's.
//
// # Linux
//
// The Linux adapter speaks netlink, can work on another network namespace
// ([NewInNamespace]), tags routes and rules with the owner's route
// protocol ([Owner.RouteProtocol]: 84, 85, 86), and holds an exclusive
// flock per namespace and owner under [LockDir], so routes and rules with
// its protocol that it finds are a dead predecessor's. Rules go in after
// the routes they lead to, and leave before. A rule keeps its protocol
// only since Linux 4.17: the adapter checks that the rules it added came
// back carrying it, and on an older kernel deletes them and fails with
// errors.ErrUnsupported rather than leave rules it can't tell from
// anyone else's. Scoped routes are refused (errors.ErrUnsupported): Linux
// sockets bypass the tunnel by their mark instead.
//
// # macOS
//
// The macOS adapter (overlay and route table only) owns routes through a
// routing socket: PF_ROUTE messages for changes, sysctl RIB dumps parsed
// with golang.org/x/net/route, interface ioctls (and ifconfig(8) to remove
// an IPv6 address, whose ioctl's struct size isn't stable across
// releases). macOS has no route metrics, tables, throw routes or policy
// rules, and the OS's default routes stay as they are: a Config with any
// of them, or with a default route, fails with errors.ErrUnsupported.
//
// Each route an owner adds carries RTF_PROTO2 and is listed in its
// owner's record (<owner>.routes) next to the owner's lock (<owner>.lock)
// in [LockDir], /private/var/db/thinkpol/netcfg. Both are needed: other
// software uses the protocol flags too (RTF_PROTO1 is common among VPN
// clients, RTF_PROTO3 is the kernel's mark on cloned routes), so a route
// is an owner's only if it carries the flag and its record names it. The
// directory is opened like the agent's lock, through package trusteddir
// (made if missing; it and every directory above it checked), since the
// record decides which routes are deleted; every record is read and
// written relative to the directory's descriptor. The record is written
// ahead of every change: every route an Apply may add is recorded before
// any is added, so a crash halfway leaves none unrecorded, and it is
// rewritten after each Apply and Close. A record carries the boot session
// it was written in ([trusteddir.BootSession], kern.bootsessionuuid): the
// directory outlives a reboot and the routes don't, so a record of an
// earlier boot owns nothing (the records are void after a reboot, like
// the routes). A corrupt record (no boot line, a line that isn't an
// identity, not a regular file, a symlink) says nothing of which routes
// are its owner's, so it owns nothing: to every other owner its routes
// count as foreign, which none removes or changes. Only its own owner
// moves it, at start and under its lock: renamed
// <owner>.routes.corrupt-<boot session>, so the owner's configurator
// starts (removing an earlier set-aside entry of the other kind, file or
// empty directory, that renameat(2) won't replace); its set-aside records
// of earlier boots are removed then. Another owner's corrupt record is left where it is, never
// touched: its owner sets it aside at its next start, or, still running,
// rewrites it at its next change (its own routes it knows from memory, and
// removes at Close). There is no darwin supervisor, so a corrupt
// supervisor.routes is never set aside: it is reported in place until
// someone removes it. Only a person makes one on a Mac; the report says
// where it is, and skipping the owner instead would also change what a
// valid one means (its routes from thinkpol's to foreign).
// [Survey.CorruptRecords] reports this boot's corrupt records, set aside
// or in place, each with why it is corrupt and when it was last written,
// for as long as they are there. One whose content proves nothing of its
// boot (no boot line, not a regular file, a symlink) and was last written
// before this boot (kern.boottime) is set aside but not reported, since
// what it named went with that boot: it leaves no trace but the file, no
// log line and no health problem. One whose boot line names this boot is
// reported whatever its mtime. [Survey.UnownedRoutes] counts the routes
// with routeFlag that no record names: with a corrupt record, the routes
// it named. A running owner's are still removed by that owner; a dead
// one's stay until reboot or until someone removes them. Any other failure
// to read a record is an error, not an empty record.
//
// A route's identity is its destination and, if scoped (RTF_IFSCOPE,
// route(8)'s -ifscope: only sockets bound to the interface use it), its
// interface, recorded by index; a scoped route never shares an identity
// with an unscoped one. A route of ours that must lead elsewhere (a new
// gateway after a network change) is changed in place (RTM_CHANGE), so
// traffic never falls through to the next route meanwhile; where the
// kernel refuses, it is deleted and added. A point-to-point interface (a
// utun) routes only its peer address, so the adapter routes the networks
// of its addresses into it as their two halves ([ConnectedRoutes]),
// owned like any other route, leaving room for a route of the whole
// network behind them (the route table's reject route, which outlives the
// utun).
//
// [Survey] on macOS reports the interfaces' subnets (the kernel's cloning
// routes for their addresses, [Survey.OnLink]), the unscoped usable
// default routes no owner added ([Survey.Defaults]: the primary service's,
// which macOS keeps unscoped), every other unscoped route no owner added
// that could take traffic ahead of the tunnel ([Survey.Routes]), and the
// identities foreign routes hold ([Survey.Held], [Survey.HeldScoped]),
// which owners' routes must not take. Loopback's routes, reject and
// blackhole routes, the kernel's clones, local and broadcast entries and
// ICMP redirects' host routes are left out of Routes. [DefaultInterface]
// asks the kernel for the default route's interface on each call
// (RTM_GET), for sockets bound to it.
//
// # Reading back
//
// [Inspect] reads, for diagnostics (`thinkpol diag`), the routes and
// rules the owners hold as the kernel reports them, changing nothing and
// whether or not a configurator runs. On Linux that is every table's
// routes and both families' rules carrying an owner's protocol (84 to
// 86), with the kernel's own table numbers, metrics and types; a rule
// with a selector netcfg never sets is shown as far as [HostRule] goes and
// flagged. On macOS it is the routes carrying RTF_PROTO2 that an owner's
// record names, as the routing table holds them, reading the records
// without making LockDir or taking a lock; macOS has no rules. Where
// netcfg has no adapter, both lists are unreadable.
//
// # Watching
//
// [Configurator.Watch] signals, coalesced, the events that may call for
// an Apply. On Linux (rtnetlink): a link that came, went or changed flags
// (a TUN going down takes its routes along without a word for IPv4), an
// on-link route of the kernel's in main that came or went, a main-table
// default route of no owner that came or went, and a route or rule of
// this owner deleted. On macOS (the routing socket): an interface or its
// addresses changed, an unscoped route came, went or changed (but for
// thinkpol's own adds), and a scoped route of thinkpol's went; the
// kernel's clones never count. A lost burst (ENOBUFS) signals too.
package netcfg
