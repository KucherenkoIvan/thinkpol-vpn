---
id: TP-094
title: "macOS local API: group membership as the file system sees it"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/desktop-client.md#the-local-api]
needs_human: macos
owner: "agent-claude-tp094"
branch: "tp-094-macos-localapi-group-membership"
---

## Goal
On macOS, a member of the `thinkpol` group can do what DESIGN.md says members may do (status, connect, disconnect, rule presets), including right after being added, without logging out. The per-call check agrees with the socket directory's file-system gate.

## Scope
- The per-call check (`internal/agent/localapi/auth.go`, `Policy.Access`) takes groups from `LOCAL_PEERCRED` (`peercred_darwin.go`): the groups the client process was given at login. macOS file access resolves group membership through Directory Services, so a member who passed the directory's `0750 root:thinkpol` gate can still be refused per call. When the caller's uid isn't root or the service's own user, and the gid isn't in its groups, ask Directory Services whether the uid is a member of the group:
  - cgo-free: `dsmemberutil checkmembership -U <user> -G <group>` (or `-u`/`-g` by number);
  - bounded by a timeout;
  - cached per uid for a short time;
  - an error means not a member.
- Linux is unchanged: SO_PEERGROUPS and the file system both use the process's groups.

## Acceptance
- [x] unit tests: a member by Directory Services is allowed; a non-member is refused; a lookup that fails or times out is refused
- [x] unit tests: a member whose group is past xucred's first 16 is allowed through Directory Services
- [x] `make lint` and `make test` pass
- [ ] device: `thinkpol status` as a fresh group member, without logging out, works; `thinkpol logs` stays root's only

## Notes
- **Device evidence (2026-10-16, TP-078 session A, check 05b).** The socket's directory was `drwxr-x--- root thinkpol` and the owner (a member, added by the test kit) could connect. The service answered GetStatus with `permission_denied`, and the CLI showed "only root may do that". The CLI's wording for a member who lacks the rights is wrong too: fix it here ("permission denied: …").
- Whether the client's terminal had logged in again after the group was created isn't recorded. Either way the two gates disagreed.
- **xucred holds at most 16 groups** (peercred_darwin.go): a member whose thinkpol group is past the first 16 is refused the same way; the Directory Services fallback covers it.
- **Device evidence (the 2026-10-24 macOS device run, service install steps 2 and 3).** The member was still refused after logging out and in: `thinkpol status` and `thinkpol diag` both said `permission denied: only root may do that`. The owner is in 19 groups, and the check reads only the first 16 (`cred.Groups[:n]`, n ≤ 16, `peercred_darwin.go` ~19–25). On 2026-10-16 the group was the owner's 2nd and the member was refused too, so the 16-group cut may not be the whole cause: have a refusal log the caller's uid and gids, so the next run can tell. `id -Gn` already lists the group before the re-login, because it asks Directory Services: it can't show what the session holds.
- **Order (owner, 2026-10-24).** In the before-M2 list (wave 1, macOS): done before the M2 lanes start. It fails every device run's member checks.
- **Device checklist (for TP-144's re-run, macOS).** With this branch's build installed as the service (`service install`, as in TP-046's checklist), in a terminal that has *not* logged in again since the `thinkpol` group was made, as yourself; `sudo` only where shown. Record each Expect as PASS or FAIL with what it printed.
  1. **Do:**
     ```sh
     id -u; dscl . -read /Groups/thinkpol PrimaryGroupID
     thinkpol status; echo "exit $?"
     thinkpol diag > /dev/null; echo "exit $?"
     ```
     **What happens:** each call's credentials lack the group (the login's first 16 groups don't have it), so the service asks Directory Services by uid and gid.
     **Expect:** the status prints and both exits are 0.
  2. **Do:**
     ```sh
     thinkpol logs -n 5; echo "exit $?"
     sudo thinkpol logs -n 200 | grep 'local API call refused'
     ```
     **What happens:** the log is root's only, so the member's call is refused and the service logs the refusal.
     **Expect:** the first command says `permission denied: the status and the controls are for root and the local API's group, the log for root ...` and exits non-zero. The grep shows a line with `method=/thinkpol.localapi.v1.LocalService/TailLogs`, `uid=` your uid, `needs=admin`, `has=control`, `group=` the gid from step 1 and `recorded_groups=` a number (16 with 19 groups), and no refused `GetStatus` or `Diagnose` line from step 1.
  3. **Do:** (a fresh member, without logging out)
     ```sh
     sudo dseditgroup -o edit -d "$USER" -t user thinkpol
     sleep 11; thinkpol status; echo "exit $?"
     sudo dseditgroup -o edit -a "$USER" -t user thinkpol
     sleep 11; thinkpol status; echo "exit $?"
     ```
     **What happens:** out of the group you're refused, at the socket's directory or per call; added back, Directory Services says you're a member and the service's kept answer (10 s) has expired.
     **Expect:** the first status fails with `permission denied` (exit non-zero); the second prints the status (exit 0). If the second still fails, run it again after a minute and record both: the file system may cache membership for longer.

## Review findings
Round 1 (paranoid: correctness; torvalds: design; go-style: conventions; the cross-family log was empty).
- [ ] R1.1 (paranoid 1, torvalds 5, go-style 3): RR43, doc.go and membership.go say a removed user loses control within 10 s. Removal takes effect at the user's next login when their session carries the group, and within 10 s only when it never did; an open WatchStatus stream isn't re-checked until the client reconnects, on every OS. The cache is per uid and group.
- [ ] R1.2 (torvalds 1): a Directory Services failure is reported as "permission denied". Refuse it (fail closed) as a distinct `membership_unknown` / codes.Unavailable with "try again" wording; keep a failure about 2 s so callers fail fast.
- [ ] R1.3 (torvalds 2): the refusal points non-root users at a root-only log, and one message covers two cases. Split `root_only` (a member asking for a root call) from `permission_denied` (not root, not in the group); one phrasing shared with client.go's dial-time message, the wording in one table (TP-139 F9); `errors.Is` callers keep working (`IsPermission`).
- [ ] R1.4 (paranoid 2, torvalds 3): no test for the one-lookup-at-a-time slot, the re-check after taking it, or a cancelled waiter; the loop that drops expired answers isn't exercised.
- [ ] R1.5 (go-style 1): the "701" log assertion can match the timestamp's milliseconds.
- [ ] R1.6 (go-style 2): doc.go says every refusal is logged with all fields; the no-credentials refusal logs only the method, `group` only with a group.
- [ ] R1.7 (torvalds 6): the cache takes a bare func; make it wrap a Membership (one signature, no test adapter).
- [ ] R1.8 (torvalds 4, paranoid 3): the membership error repeats uid and gid and drops dsmemberutil's stderr; a timeout reads "signal: killed".
- [ ] R1.9 (torvalds 9, paranoid 3): bound the wait for a killed dsmemberutil (`cmd.WaitDelay`).
- [ ] R1.10 (torvalds 8): two Directory Services timeouts (5 s, 3 s); one constant.
- [ ] R1.11 (torvalds 10, paranoid 4): Diagnose asks Directory Services to rule out admin; admin is by uid (`isAdmin`), in `access` too.
- [ ] R1.12 (torvalds 7, go-style 6, 8 and unranked): naming: `one` → `lookupSlot`; `Access` vs `access`; the `Members` field reads like a list; `keep`'s loop shadows `k`.
- [ ] R1.13 (go-style 4, 5): NewPolicy: indent the error flow; its doc says it sets the membership lookup.
- [ ] R1.14 (go-style 9): split the tests that test several things, or name the cases with t.Run.
- [ ] R1.15 (paranoid 6): the lab test's uid check is a substring match.
- [ ] R1.16 (go-style 7): the cache's comments leave out its size limit.
- [ ] R1.17 (paranoid 5): the real Directory Services test's assumptions (the effective gid is a group DS counts, the first query answers within the timeout) are unstated.

## Log
- 2026-10-16 created in backlog (TP-078 device session A)
- 2026-10-19 docs (TP-099): the 16-group xucred limit is the second cause, in Notes and Acceptance
- 2026-10-24 docs: device evidence from the 2026-10-24 macOS device run (refused after re-login; 19 groups, 16 read); before-M2 list
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, macOS)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp094
- 2026-10-28 done: `Policy.Members` (auth.go) asks Directory Services when the caller's recorded groups lack the group: `dsmemberutil checkmembership -u <uid> -g <gid>` (group_darwin.go), the ticket's approach, chosen over a cgo membership API because the build is cgo-free and dsmemberutil asks what the file system's gate asks; behind `cachedMembership` (membership.go): 3 s timeout, one lookup at a time, answers kept 10 s per uid and gid (max 64), failures and unexpected output never kept and not a member. Linux unchanged (no Members). Refusals logged at info with uid, method, needs/has, the group's gid and the recorded groups' count, not the list (the ticket's Notes asked for gids; the orchestrator's brief said the needed group only); CLI refusal wording now names root, the group and the log. Docs: localapi doc.go, desktop-client.md, RR43 (narrowed to the 10 s cache window).
- 2026-10-28 tests: membership_test.go (DS member allowed, past-16 member allowed, non-member refused, failed and timed-out lookups refused, not asked when credentials settle it, cache kept/expired/failures not kept/bounded, refusal log has uid and group and not the groups), group_darwin_test.go (dsmemberutil argv and answer parsing, fail-closed on errors and odd output; a read-only real Directory Services query), TestPolicy (NewPolicy sets Members only on macOS with a group). Mutations, each failing a test: no DS fallback; lookup error ignored; recorded groups skipped; no-group short-circuit removed; nothing cached; failures cached; no timeout; a late answer counted; cache unbounded; ttl ignored; uid not logged; group not logged; groups listed in the log; member sentence unknown; unexpected answer counted as member; exec error ignored; NewPolicy without Members.
- 2026-10-28 not verified: the service on a real Mac as root with a 19-group member (device checklist in Notes, for TP-144); whether the file system's own membership cache can lag behind the 10 s answer after a group change (checklist step 3 records it).
- 2026-10-28 lab: TestLocalAPI's "the log is root's" now checks the new wording and the refusal's log line (uid, group, needs=admin); mutation: the refusal not logged, the lab test fails. `make lab-test` green on 0d87348 (`make lint`, `make test` green too).
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 1: R1.1–R1.17)
