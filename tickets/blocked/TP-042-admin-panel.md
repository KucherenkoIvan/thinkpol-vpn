---
id: TP-042
title: "Admin panel and dashboards"
milestone: M4
area: features
repo: thinkpol-vpn
size: L
depends_on: [TP-035, TP-041, TP-086]
refs: [A6, A8]
owner: ""
branch: ""
---

## Goal
The space is managed from a web panel reachable only through the overlay.

## Scope
- `webui` pages: spaces, members, nodes (ingress/egress toggles), chains, rules, invites, grants.
- Dashboards: node health, connected devices, traffic rates, transports in use, active routes, failures per transport and entry.

## Acceptance
- [ ] everything the admin CLI can do is possible from the panel
- [ ] the panel isn't reachable on a public address

## Blocked by
The admin panel's organisation, authentication and authorization are not designed (DESIGN "Open questions"); no ticket owns that design yet. Only the author can provide it.

## Notes
- **List provenance and attribution (from TP-016 review):** wherever the panel shows GeoIP lists, it shows each list's source (e.g. DB-IP Lite 2026-10, or a v2fly release), its license and the attribution the license asks for: `lists.Format.Attribution()`, e.g. "IP Geolocation by DB-IP (CC BY 4.0)". A blob holds only prefixes, so the controller stores source and attribution next to each list it builds.
- **Don't start before the panel's design exists (TP-062).** Its organisation, authentication and authorization are on hold: the owner hasn't decided (independent design review, 2026-10-13; DESIGN "Open questions"). Overlay reachability is not access control: members' devices are on the overlay by design and the controller holds the signing key. When the design is written, put it in DESIGN.md and add its acceptance here.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 notes from TP-016 review: list provenance and attribution in the panel
- 2026-10-13 docs (TP-062): do not start before the panel's authn/authz design exists (blocking note)
- 2026-10-15 backlog → blocked — panel authn/authz design missing (backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): Blocked by names who can unblock
- 2026-10-15 docs: depends on TP-086 (frontend stack revisit)
