---
id: TP-060
title: "A second `thinkpol up` must not undo a running agent's DNS (Linux)"
milestone: M1
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-020, TP-022]
owner: "cursor-opus-tp060"
branch: "tp-060-agent-lock-linux"
---

## Goal
On Linux, a second `thinkpol up` on a node where an agent is already running does not touch the host. Today it runs the start-up DNS restore (resolv.conf, or systemd-resolved) before it fails at netcfg's per-owner lock, so the running agent's DNS is undone while its tunnel stays up. After this, the second start is refused before any cleanup, and the running agent's DNS stays as it was. This brings Linux in line with macOS, where TP-019 takes a host-wide agent lock before the start-time cleanups.

## Scope
- Take a host-wide agent lock on Linux (`/var/run/thinkpol/agent.lock`, flock, the same path and semantics as the macOS `hostLock` in TP-019) at the start of `thinkpol up`, before any start-up cleanup: the DNS restore and the route-table clear.
- A second start that cannot get the lock exits with "another agent is running" and changes nothing on the host.
- The lock is released when the agent exits, as on macOS.

## Out of scope
- macOS: TP-019 owns its lock.
- The per-owner netcfg lock and its semantics stay as they are; the host lock sits in front of it.
- Installing the agent as a service and the lock's ownership under systemd (TP-046).

## Acceptance
- [x] lab test: start agent A on a node; start agent B on the same node. B exits with "another agent is running", and A's DNS config (resolv.conf, or the systemd-resolved state if that is what A set) is unchanged, compared before and after B's run — `lab/agentlock_test.go` `TestASecondAgentChangesNothing`: device-a (resolv.conf) and device-b (systemd-resolved) connected on the DNS lab map; `thinkpol up` and `thinkpol up -connect=false` beside each exit 1 with "another thinkpol agent is running on this host"; unchanged before/after: resolv.conf's content, inode and mtime, `resolvectl dns`/`domain`/`default-route thinkpol0`, `ip rule`/`ip -6 rule`, every route table, `ip -br addr`; `ip monitor link address route rule` shows nothing between two marker rules around B's runs; A's status still `connected`, it still resolves a tunnel name and pings server-1. Passes; with the lock stubbed out it fails (resolv.conf rewritten under A, the `-connect=false` B stays up beside A)
- [x] `make lint` and `make test` pass — both on the final commit; `make lab-test` too (lab tests ok, `gotest: ok, 28 packages`)

## Notes
- Found in TP-019's review (branch `tp-019-macos-data-plane`, round 2 notes): on Linux a second `thinkpol up` fails at netcfg's per-owner lock only after its start-time resolv.conf restore, which undoes the running agent's DNS. macOS has the host lock (`hostLock`) for this; Linux could take the same before the cleanups.
- The start-time cleanups are `dns.RestoreSystem` and `routetable.Clear`. The lock has to come before both, and before anything else that writes to the host.

**Built (TP-060):**
- **One lock for Linux and macOS** (`internal/agent/hostlock_unix.go`, `linux || darwin`): TP-019's `hostLock` body, made a shared `lockHostAt(path)`: the lock's directory is created 0700 and must be a real directory of the euid that no one else can write to; the file is opened `O_CREAT|O_CLOEXEC|O_NOFOLLOW` 0600 and `flock(LOCK_EX|LOCK_NB)`ed; `EWOULDBLOCK` is `errAnotherAgent` ("another thinkpol agent is running on this host (it holds <path>)"). Path per OS: `/run/thinkpol/agent.lock` on Linux (next to netcfg's locks; the same file as the ticket's `/var/run/thinkpol/agent.lock` wherever `/var/run` links to `/run`), `/var/run/thinkpol/agent.lock` on macOS (no `/run`); `hostlock_other.go` (`!linux && !darwin`) takes nothing, behind `supported`.
- **Where it is taken: `Node.Adapters`, not `run`** (unlike TP-019): right after `supported()`, before the transport registry and before `cmd/thinkpol/up.go` adds the local API adapter, which `app.Run` starts beside the node and whose `Listen` may fix the API directory's group and mode (a second `up` with another `-api-group` would have changed the running agent's API access before `run`'s lock). Released when the node adapter returns (after the data plane's own undo), or when the process dies. Close-on-exec: a server's workers never hold it (unit test with a child process; it fails without `O_CLOEXEC`).
- **Hooks** (TP-019's, verbatim): `clearHostRouteTable`, `restoreHostDNS`, `lockHost` package variables in `node.go`; `host_test.go`'s `TestMain` stubs the cleanups outside the lab and the lock everywhere (a test's node isn't the host's agent; the lock has its own tests on temporary paths, `hostlock_unix_test.go`).
- **DESIGN.md** "Engine and agent": one agent per host, the lock, what a second `thinkpol up` does.

**For whoever merges TP-019 (or this) second:** take this branch's `hostlock_unix.go`, `hostlock_darwin.go` (path only), `hostlock_other.go` and `host_test.go`; in `node.go` drop TP-019's `lockHost()` call at the top of `run` (Adapters takes it) and keep its `supported(n.mode)`; TP-019's macOS behavior is unchanged otherwise. The message is now "another thinkpol agent is running on this host".

**Found on the way:** without the lock a second `thinkpol up -connect=false` doesn't exit at all on Linux: its route-table clear fails at netcfg's per-owner lock (logged as a warning), its local API at `api.lock`, and it then runs disconnected beside the first agent, following maps. The lock ends that too.

**Not done:** the lock under systemd (TP-046): a `RuntimeDirectory=` for `/run/thinkpol` must leave it root's and writable by no one else, or the agent lock refuses it.

**Review follow-ups (pl-paranoid, verdict MERGE):**
- **Merge hazard with TP-019:** TP-019's own `lockHost()` call at the top of `run` would merge cleanly but makes every `thinkpol up` fail (the lock is taken twice in-process, so the second `flock` gets `EWOULDBLOCK`). Unit tests stub `lockHost`, so only the Linux lab test catches it. Whoever merges TP-019 must keep only the call in `Node.Adapters` and use TP-060's `hostlock_*.go`.
- **Lab test gap (low):** `agentlock_test` doesn't check the local API directory's group and mode, so moving the lock back into `run` would still pass. Pin it by stat'ing the API directory and starting B with a different `-api-group`.

## Log
- 2026-10-13 created in backlog
- 2026-10-13 backlog → in-progress — owner: cursor-opus-tp060, branch: tp-060-agent-lock-linux
- 2026-10-13 in-progress → review — DESIGN.md "Engine and agent" updated (one agent per host, the agent lock); the lock is taken in `Node.Adapters`, not `run` as in TP-019 (see Notes)
- 2026-10-13 review → done — reviewed (pl-paranoid: MERGE), merged into rewrite
