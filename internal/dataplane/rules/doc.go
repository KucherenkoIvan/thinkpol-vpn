// Package rules turns a device's routing rules into what enforces them
// (DESIGN.md "Routing rules and DNS"). The rule format itself (netmap.Rule,
// netmap.ParseRule) is the map's.
//
// # Rules
//
// A rule is a matcher and an action; the first rule that matches a
// destination decides it. Actions:
//
//   - direct: around the tunnel;
//   - chain:<name>: through the chain's exit;
//   - block.
//
// Matchers:
//
//   - default: every address;
//   - local: the built-in local ranges ([lists.Local]: LANs, link-local,
//     multicast, broadcast), never 100.64.0.0/10, the overlay's range;
//   - cidr:<prefix>: the prefix. IPv4 is matched only as IPv4, so an IPv6
//     prefix around ::ffff:0:0/96, such as ::/0, leaves that range out, and
//     one inside it counts as a matcher the node doesn't know (below);
//   - geoip:<list>: a GeoIP list, a blob the node's section names
//     (package lists, fetched by dataplane/blobs);
//   - domain:, domain-suffix: and geosite: match names. They are kept in
//     the map and enforced by DNS and, later, by userspace mode, never by
//     the route table.
//
// # Where a device's rules come from
//
// The space's default list lives in the signed map, in each device's
// section, with the chains it names (name → exit; at M1 a chain is its
// exit node) and what the presets are built from: a domestic GeoIP list and
// a chain (netmap.RulePresets). The map's builder requires the list to end
// with default, so every destination has an action.
//
// Each device can override it locally (the "what goes through the tunnel"
// switch): a local file ([Local]: rules.local in the state directory,
// written only by the service through the local API) picks a base, either
// the space's rules or a preset, and the device's own rules go ahead of it.
// [Effective] puts them in order. The presets ([PresetRules]):
//
//   - everything: local → direct, default → chain:<the presets' chain>;
//   - all but domestic: the same with geoip:<domestic> → direct after
//     local.
//
// A preset the map can't build fails closed, never back to the space's
// rules, which may send more around the tunnel than the device asked for:
// "all but domestic" without a domestic list is "everything", and either
// without a chain sends only local direct and blocks the rest
// ([ErrPresetUnavailable]).
//
// Rules don't raise the section reader (netmap.SectionReader): a node too
// old to know them ignores them and routes nothing outside the overlay
// into the tunnel, as on M0, and keeps following the space's maps and
// their revocations.
//
// # Compiling to prefixes
//
// The space's overlay networks are decided first, by the overlay's peers,
// whatever the rules say. [Compile] resolves first-match-wins over the rest
// into a [Table]: disjoint prefixes, IPv4 and IPv6, covering every address
// outside the overlay networks, one action each. [Table.Routes] are its
// longest-prefix table: per address family a /0 route for the action with
// the most prefixes, and every other action's prefixes, which never overlap
// one another or the overlay, so a longest-prefix match (the router's)
// finds exactly the action of the first matching rule. The rest of the
// world around a country's list fragments into many times its prefixes, so
// the /0 keeps the table at about the size of the list: RU's "all but
// domestic" is some 22 thousand routes. [Table.Direct] is the set
// route-table mode installs around the tunnel.
//
// Route-table mode matches addresses only. Rules it can't enforce are kept
// and reported ([Skip], with a [Reason]), never silently dropped, and
// nothing a node can't resolve ever widens what goes direct:
//
//   - domain, domain-suffix and geosite rules match no address (DNS and,
//     later, userspace mode enforce them); one that doesn't go direct and
//     is followed by a direct rule is reported as undercut, since that
//     rule may send its names' addresses around the tunnel;
//   - a rule whose addresses aren't known (a GeoIP list the node doesn't
//     have yet, a matcher it doesn't know) matches nothing, and unless it
//     was a direct rule itself, every later direct rule is off too, since
//     its addresses might have been the unknown rule's;
//   - an unknown action, or a chain whose exit isn't a usable peer
//     (Options.Chain), blocks;
//   - a destination no rule matches is blocked; with no rules at all,
//     nothing goes through the tunnel (everything is direct).
//
// The exit of each chain some rule sends traffic to ([Table.Chains]) gets
// a WireGuard device of its own (package dataplane's layout, package wg),
// whose allowed IPs are the internet and, of the overlay, only the exit's
// own addresses, so an exit can't pass its packets off as another peer's.
//
// # Names
//
// [CompileNames] reads the same list by name, for the DNS resolver: which
// upstream answers a name ([Names]).
package rules
