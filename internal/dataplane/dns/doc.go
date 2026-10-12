// Package dns is the resolver on the node's overlay address (DESIGN.md
// "DNS is routing").
//
// On a device ([Server] with a device's [Config]) it answers the space's
// overlay names, `<node>.<space>.internal`, from the map (only the nodes
// the device has as peers, and itself), and resolves every other name by
// the device's routing rules: a name the rules send direct is asked of the
// domestic upstream ([Options.Upstreams], what the OS used before), any
// other through the tunnel, of the resolver at its chain's exit, and a
// blocked one of no one. Nothing under `.internal` and no reverse name of
// the overlay is ever forwarded. Answers are cached per route, so a direct
// upstream's answer is never served for a name that goes through the
// tunnel; the cache is bounded and flushed whenever the configuration
// changes.
//
// On an exit (a server that allows egress) the same server is the
// resolver at the exit: it takes queries from the space's overlay only and
// asks its own upstream.
//
// Nothing is logged about a query: names and answers never reach a log or
// the disk (DESIGN.md "Node safety"); [Server.Counters] are the only
// figures. Forwarded queries carry no EDNS options of the client's
// (subnet, cookies), so a client's addresses don't travel upstream.
//
// [SetSystem] points the OS resolver at the server and puts the old
// configuration back on Restore: systemd-resolved over D-Bus when the OS
// resolves through it, /etc/resolv.conf otherwise (Linux; macOS is
// TP-019's).
package dns
