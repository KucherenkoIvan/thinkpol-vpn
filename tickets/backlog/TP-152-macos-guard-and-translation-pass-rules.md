---
id: TP-152
title: "macOS guard: `nat pass`, `binat pass` and `rdr pass` skip it unseen"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: M
depends_on: [TP-129]
refs: [RR12]
owner: ""
branch: ""
---

## Goal
A translation rule with `pass` that lets outgoing IPv6 around the guard is either reported (the guard not enforced) or accepted with its reason written down in RR12.

## Scope
- pf passes what a `nat pass`, `binat pass` or `rdr pass` rule translates without evaluating the filter rules, so the guard's anchor never sees it. `pfctl -s rules` doesn't list translation rules, so `checkBypass` / `anchorWalk` (guard_darwin.go, TP-129's branch) can't see them, and `anchorRule` skips `nat-anchor` / `rdr-anchor` / `binat-anchor` calls.
- Decide one, and say why in Notes:
  - **Read them**: the check also reads `pfctl -s nat` (main ruleset down to the hook, and the translation anchors it calls, under the same 16-anchor bound) and reports a `pass` translation rule that can match outgoing IPv6 as a bypass. Say what it costs per poll on a stock Mac.
  - **Accept**: RR12 says why (e.g. how rare such rules are, what other software adds them), and firewall/doc.go's "doesn't do" list keeps it.
- `rdr` translates incoming packets: say whether `rdr pass` can matter for outgoing IPv6 at all (loopback re-entry), and leave it out if not.

## Out of scope
- Diagnostics for the anchor walk: TP-151.
- Undoing other software's pf rules: the guard reports, never undoes (TP-126).

## Acceptance
- [ ] the decision and its reason are in Notes, RR12 and firewall/doc.go
- [ ] if read: a fake-pfctl test where a `nat pass` matching outgoing IPv6 makes the guard not enforced (mutation: not reading `-s nat` fails it), one where an inet-only `nat pass` doesn't, and a device item in TP-096 for the real `-s nat` listing
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-129 implementer's Log and its reviews (RR12 on TP-129's branch already names `nat pass` and `binat pass` as unseen).

## Log
- 2026-10-29 created in backlog (TP-129 implementer and reviews)
