// Package rules turns a device's routing rules into what enforces them
// (DESIGN.md "Routing rules and DNS").
//
// A device's rules are its own, from a local file ([Local]), on top of a
// base: the space's default rules from the map, or a preset built from the
// map's preset settings ("everything", "all but domestic"). [Effective]
// puts them in order; the first rule that matches a destination decides it.
//
// [Compile] resolves first-match-wins into a [Table]: disjoint prefixes,
// IPv4 and IPv6, covering every address outside the space's overlay
// networks, one action each. Because no two overlap, a longest-prefix match
// (the router's) finds exactly the action of the first matching rule.
// [Table.Direct] is the set route-table mode installs around the tunnel.
//
// Route-table mode matches addresses only. Rules it can't enforce are kept
// and reported ([Skip]), never silently dropped, and nothing unknown ever
// widens what goes direct:
//
//   - domain, domain-suffix and geosite rules match no address (DNS and,
//     later, userspace mode enforce them);
//   - a rule whose addresses aren't known (a GeoIP list the node doesn't
//     have yet, a matcher it doesn't know) matches nothing, and if it
//     doesn't send traffic direct, every later direct rule is off too, since
//     its addresses might have been the unknown rule's;
//   - an unknown action, or a chain that can't carry traffic, blocks;
//   - a destination no rule matches is blocked; with no rules at all,
//     nothing goes through the tunnel (everything is direct).
package rules
