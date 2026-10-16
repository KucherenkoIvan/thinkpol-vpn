---
id: TP-094
title: "macOS local API: group membership as the file system sees it"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
refs: [DESIGN#the-local-api]
needs_human: macos
owner: ""
branch: ""
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
- [ ] unit tests: a member by Directory Services is allowed; a non-member is refused; a lookup that fails or times out is refused
- [ ] `make lint` and `make test` pass
- [ ] device: `thinkpol status` as a fresh group member, without logging out, works; `thinkpol logs` stays root's only

## Notes
- **Device evidence (2026-10-16, TP-078 session A, check 05b).** The socket's directory was `drwxr-x--- root thinkpol` and the owner (a member, added by the test kit) could connect. The service answered GetStatus with `permission_denied`, and the CLI showed "only root may do that". The CLI's wording for a member who lacks the rights is wrong too: fix it here ("permission denied: …").
- Whether the client's terminal had logged in again after the group was created isn't recorded. Either way the two gates disagreed.

## Log
- 2026-10-16 created in backlog (TP-078 device session A)
