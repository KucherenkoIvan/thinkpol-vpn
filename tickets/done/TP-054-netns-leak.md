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
- [x] no helper leaves a thread in another namespace: restores both namespaces, unlocks only when restored, stays locked (and logs loudly on the main thread) when not — `nsthread.Do`, see Notes
- [x] every `LockOSThread` / `setns` / `unshare` site audited; each fixed or noted here as not applicable — see "Audit" in Notes
- [x] lab regression tests: ~200 calls per helper, then every task's net and mnt namespace equals the root's; shown to fail without the fix — `TestDoLeavesNoThreadBehind`, `TestSetNetSysctlsLeavesNoThreadBehind`, `TestCreateInNamespaceLeavesNoThreadBehind`; old code fails 8/8 (callers) and 7/8 (`nsthread` with the restore skipped), fixed code 10/10 green
- [x] `TestWorkersAreSandboxed` unchanged and green (5 extra full runs of the supervisor package in the lab, all green)
- [x] `TestCommandStartsSealed` reads only a complete snapshot (written to `/tmp/at-start.tmp`, then `mv`)
- [x] `make lint`, `make test`, race on the touched packages, `make lab-gotest PKG=./internal/agent/...` and `PKG=./internal/dataplane/tun/...`, `make lab-test` green

## Notes
- **Fix: `internal/dataplane/nsthread`** (new, Linux; DESIGN.md "Repository layout" and the dataplane package doc list it). `Do(fn)` runs fn on a fresh goroutine locked to its thread. Before fn it opens the thread's own `/proc/thread-self/ns` directory (O_PATH, so it stays readable after fn enters a mount namespace without this /proc) and its `net` and `mnt` namespaces. After fn it compares each current namespace (dev, inode) with the saved one and `setns`es back into whichever moved, then checks again. It unlocks the thread only if nothing moved or everything was restored **and the mount namespace never moved**: leaving the mount namespace (`unshare(CLONE_NEWNS)` or `setns`) unshares the thread's filesystem attributes (root, cwd, umask) for good, and `setns` back can't re-share them, so such a thread is never reused. Its goroutine ends locked and Go ends the thread, or parks it if it is the main thread; that's harmless now because the thread is already back in the process's namespaces. If a restore fails, `Do` returns fn's error joined with the restore's, keeps the thread locked and logs `slog.Error` with `main_thread=true|false`. Unchanged namespaces are never `setns`ed into: a mount `setns` from a thread that still shares its filesystem attributes fails with EINVAL.
- **Why restore in-thread and not a helper process:** `tun.CreateInNamespace` has to return a live device whose TUN fd and netlink socket were created in the target namespace. A helper process would have to pass both back over SCM_RIGHTS and rebuild wireguard-go's device around them. The sysctl helper could run in a process, but it would cost a fork and exec per space start. The in-thread round trip is the same pattern mdlayher/socket uses for its netns sockets.
- **Callers:** `setNetSysctls` (supervisor, unchanged mechanism: a private mount ns, `setns` into the space, a fresh proc, write, unmount) and `tun.CreateInNamespace` (closes the device if `Do` fails after creating it) go through `Do`.
- **Audit** (`LockOSThread`, `Setns`, `Unshare`, `CLONE_NEW*`, `netns.Set/Do`, after merging TP-011 and TP-012):
  - `supervisor.setNetSysctls`, `tun.CreateInNamespace`: fixed (above).
  - `supervisor.start` (`supervisor_linux.go`): locks the thread for the worker's lifetime so its parent-death signal is tied to a living thread. It changes no namespace. Not applicable.
  - `supervisor_linux.go` `SysProcAttr.Cloneflags`: the namespaces are the child's, created by clone. No thread of ours moves. Not applicable.
  - `netcfg.New` (`netcfg_linux.go`, from TP-011): locks only to read the current thread's namespace. Not applicable.
  - `runEscapeControl` (supervisor test): runs in a child test process that `unshare`s and exits. Not applicable.
  - Third-party: vishvananda/netlink's `NewHandleAt` (used by `netcfg.NewInNamespace` and the supervisor's neighbours) does its own lock, `setns`, restore round trip, but unlocks even when the move back fails. mdlayher/socket (under google/nftables' netns option) keeps the thread locked when the restore fails. Left as is: a `setns` back into the thread's own namespace through a held fd doesn't fail in practice, and patching it is out of scope.
- **Tests** (lab, `THINKPOL_LAB`): `nsthreadtest.CheckThreadsHome` fails for every `/proc/self/task/*` whose `ns/net` or `ns/mnt` differs from pid 1's (the lab node's; `docker exec` puts the test there). Each regression test makes 100 calls one after another and then 100 at once against a throwaway namespace (`ip netns add`), then checks. `TestDoLeavesNoThreadBehind` alternates net-only and net+mount round trips; `TestDoReturnsTheError` covers an fn that fails with nothing moved and one that fails after `unshare`. `TestSetNetSysctlsLeavesNoThreadBehind` also reads the written value back from the namespace (1, then 2). `TestCreateInNamespaceLeavesNoThreadBehind` uses a fresh interface name per call, because the kernel briefly still holds a just-closed TUN's name (EBUSY), and ignores `Close`'s error, because wireguard-go's `Close` races its netlink listener and can report a broken pipe while the device is gone anyway. Both were seen as flakes in the first repeat runs; neither is a namespace issue.
- **Shown to fail without the fix:** with the old `netsysctl_linux.go` and `tun_linux.go`, 4/4 runs of each caller test failed with the main thread in the throwaway namespace (`thread 47 (main thread: true) is in net namespace net:[…]`, plus `mnt` for the sysctls). The same happened with `nsthread` changed to skip the restore and exit locked (7/8 runs; 200 calls are needed because the goroutine only sometimes lands on the main thread). With the fix: 10/10 repeat runs of all three regression tests are green.
- **Bug 2:** `TestCommandStartsSealed`'s command now writes `/tmp/at-start.tmp` and `mv`s it to `/tmp/at-start` (a rename in one directory, atomic), so the poll sees either nothing or the whole snapshot. `go test -tags lab -count=3 -run TestCommandStartsSealed ./lab/` green.
- **Evidence (after merging origin/rewrite with TP-011 and TP-012):**
  - `make lint` 0 issues (Android build and no-cgo check included). `make test` green.
  - `CGO_ENABLED=1 go test -race` on nsthread, tun and supervisor green on the host. The Linux-only paths can't run under race there, and lab test binaries are built without cgo.
  - `make lab-gotest PKG=./internal/agent/...` (5 packages; `TestWorkersAreSandboxed` and the new test pass), `PKG=./internal/dataplane/tun/...` and `PKG=./internal/dataplane/nsthread/...` green.
  - `make lab-test` green (lab suite, plus 22 packages in a node).

## Log
- 2026-10-12 created in in-progress — owner: agent-tp-054, branch: tp-054-netns-leak (bug from TP-011's review and a flaky TestCommandStartsSealed)
- 2026-10-12 in-progress → review — fix in 888d33c (nsthread.Do for setNetSysctls and tun.CreateInNamespace) and 8765072 (lab snapshot), merged with rewrite (TP-011, TP-012); make lint, make test, race, lab-gotest agent/tun/nsthread, make lab-test green
- 2026-10-12 review → done — merged into rewrite
