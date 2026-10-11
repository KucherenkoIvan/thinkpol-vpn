---
id: TP-054
title: "Namespace leak in supervisor helpers; lab sealing test race"
milestone: M0
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-009, TP-002]
refs: [DESIGN#repository-layout]
owner: "agent-tp-054"
branch: "tp-054-netns-leak"
---

## Goal
No OS thread of a node process is ever left in another network or mount namespace by a helper that enters one. Today `setNetSysctls` (supervisor) and `tun.CreateInNamespace` lock a goroutine to its thread, move the thread into a worker's (or a space's) network namespace, and return still locked on the assumption that Go discards the thread. When that goroutine happens to run on the process's main thread, Go parks the main thread instead, so it stays in the worker's network namespace (and, for the sysctls, a private mount namespace) for the process's lifetime: it pins the worker's network and user namespaces after the worker exits, and `/proc/<pid>/ns/net` of the supervisor shows a worker's namespace (which made `TestWorkersAreSandboxed` flaky under load). Separately, the lab test `TestCommandStartsSealed` races its own shell redirect and can read a half-written snapshot.

## Scope
- One helper that runs a function on a locked OS thread and moves that thread back into the namespaces it started in (network and mount) afterwards; the thread is returned to the scheduler only if every restore succeeded and nothing else of its state diverged; otherwise it stays locked (Go ends it, or parks it if it is the main thread, which is logged loudly).
- `setNetSysctls` and `tun.CreateInNamespace` use it.
- An audit of every other `LockOSThread` / `setns` / `unshare` site in the repo, fixed the same way or noted here as not applicable.
- Regression tests (lab): each helper called ~200 times against a throwaway namespace, then every `/proc/self/task/*/ns/{net,mnt}` equals the root's. `TestWorkersAreSandboxed`'s assertions stay unchanged.
- `lab/smoke_test.go` `TestCommandStartsSealed`: the node's snapshot appears atomically, so the poll never reads a partial file.

## Out of scope
Third-party libraries' own namespace round trips (noted below), and any other change to how workers are sandboxed.

## Acceptance
- [ ] no helper leaves a thread in another namespace: restores both namespaces, unlocks only when restored, stays locked (and logs loudly on the main thread) when not
- [ ] every `LockOSThread` / `setns` / `unshare` site audited; each fixed or noted here as not applicable
- [ ] lab regression tests: ~200 calls per helper, then every task's net and mnt namespace equals the root's; shown to fail without the fix
- [ ] `TestWorkersAreSandboxed` unchanged and green
- [ ] `TestCommandStartsSealed` reads only a complete snapshot
- [ ] `make lint`, `make test`, race on the touched packages, `make lab-gotest PKG=./internal/agent/...` and `PKG=./internal/dataplane/tun/...`, `make lab-test` green

## Notes

## Log
- 2026-10-12 created in in-progress — owner: agent-tp-054, branch: tp-054-netns-leak (bug from TP-011's review and a flaky TestCommandStartsSealed)
