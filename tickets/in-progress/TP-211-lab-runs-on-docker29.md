---
id: TP-211
title: "The lab and the tests run on a stock Linux Docker 29 host"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-211"
branch: "tp-211-lab-runs-on-docker29"
---

## Goal
`make test` and `make lab-test` pass on a stock Linux host with Docker 29 (AppArmor on, the account's umask 0002, a Go newer than go.mod's toolchain line), as they do on Docker Desktop 27, with nothing set up on the host and no overrides on the command line. Docker Desktop will move to 29 too, so the Mac's labs would break the same way.

## Scope
What a full lab and `make test` hit on such a host (measured 2026-11-14):
1. Docker 29's default seccomp profile denies `pivot_root` even with `CAP_SYS_ADMIN`: every server worker's sandbox (`internal/agent/supervisor/process_linux.go`, `internal/agent/worker/sandbox_linux.go`) dies with "sandbox: pivot_root: operation not permitted", and about 150 lab tests fail. Docker 27 allows it (see Notes: it is Docker Desktop, not the version).
2. Docker's embedded resolver at 127.0.0.11 resolves outside names from inside the lab, so `TestSmoke/hermetic` fails ("Docker's resolver answered an outside name … want SERVFAIL").
3. Tests inherit the process umask: under umask 0002 the trusted-directory checks refuse the group-writable temp directories the tests create (264 tests fail).
4. `TestTheNodeFileIsStrictJSON` asserts a JSON error's position, which changed in Go 1.27: under `GOTOOLCHAIN=auto` a host's newer Go wins, since go.mod's toolchain line is a minimum.
5. Found while fixing 1 and 2: on a host with `br_netfilter`, Docker 28+ drops every packet the router would forward between lab networks; on a stock Linux 7.0 kernel the forged-ICMP test has no `/proc/.../nf_conntrack`, and the systemd nodes' `systemctl kill` fails (see Notes).

## Out of scope
- Changing the host: everything is fixed in the repo.

## Acceptance
- [ ] The lab's nodes declare what they need, as they declare `apparmor=unconfined` in `lab/compose.go`: a seccomp setting that allows `pivot_root`, the narrowest that works, with the reason in a comment and `lab/README.md`.
- [ ] The hermetic DNS check holds on both Docker versions with no weaker oracle: the cause of the embedded resolver's answers is found and sealed in the lab's own setup; the test's tripwire is not loosened.
- [ ] Tests pass under umask 0002 and 0022: tests set the permissions they mean (explicit modes, Chmod) instead of inheriting the umask; the agent, under a root umask of 0002, doesn't create its own state or trusted directories group-writable and then refuse them (fixed here if it does and the fix is small, else named).
- [ ] `TestTheNodeFileIsStrictJSON` passes on Go 1.26.11 and 1.27.x: it asserts the error's meaning, not the stdlib's message text or position.
- [ ] A full `make lab-test` passes on a Linux Docker 29 host without umask or `GOTOOLCHAIN` overrides, and on Docker Desktop 27.

## Notes
Causes, from Docker's source (moby `docker-v29.9.3`, `v27.3.1`) and measured on a Linux Docker 29.9.3 host:
- **pivot_root.** Docker's default seccomp profile has never allowed `pivot_root`, with or without `CAP_SYS_ADMIN` (not in v27.3.1's `profiles/seccomp/default.json`, nor in moby/profiles seccomp v0.2.4, which 29.9.3 vendors). It passed on the Mac because Docker Desktop's daemon runs containers unconfined (`docker info`: `seccomp,profile=unconfined`), so the move to Docker Desktop 29 alone wouldn't have broken it. Fix: `lab/seccomp.json`, Docker 29's default profile plus one rule (`pivot_root` with `CAP_SYS_ADMIN`), declared by every node next to `apparmor=unconfined`; narrower than `seccomp=unconfined`, and the Mac's nodes now run under it too.
- **DNS.** `TransformForIntNS` (libnetwork/internal/resolvconf) marks the nameservers read from the host's resolv.conf as asked from the host's network namespace: in 29.9.3 every one of them, in 27.3.1 only loopback, zoned, or IPv6 ones on an IPv4-only network. A Linux host's systemd-resolved (127.0.0.53) is loopback, so the lab leaked there on Docker 27 too; Docker Desktop's VM resolver isn't, so it was asked from the node and the sealing stopped it. Nameservers a container is given (`dns:`) are asked from the container's namespace on both. Fix: every node's nameserver is `lab.DNSUpstream` (192.0.2.254, outside the lab), so the forward goes through the node's routes. The tripwire is stronger, not weaker: still SERVFAIL, and now the router must see the forwarded query arrive from the device and nothing leave.
- **Routing (found here, not in the orchestrator's list).** With the two fixes above, `TestSmoke/ipv4` and `/ipv6` still failed on the Linux host: nothing a device sent to a node on another lab network reached the router. Docker 28+ in the default `nat` gateway mode adds `raw PREROUTING -d <container> ! -i <its bridge> -j DROP` per container (iptabler `filterDirectAccess`), and with `br_netfilter` loaded on the host the frame a node bridges to the router for another network's node matches it. Fix: lab networks use the `routed` gateway mode (no such rule, no NAT); Docker 27.0+ accepts it, `nat-unprotected` it rejects.
- **conntrack procfs (found here).** The stock kernel is built without `CONFIG_NF_CONNTRACK_PROCFS`, which `lab/README.md` listed as a requirement for `TestForgedICMPErrorsAreRefused`. The test now reads the root's flow over netlink (`netlink.ConntrackTableList`), as the supervisor flushes it, and the requirement is gone from the README.
- **systemd kill (found here).** On the Linux 7.0 host `systemctl kill -s KILL thinkpol.service` in the systemd nodes (the image's systemd 252) failed in most runs with "Failed to send signal SIGKILL to auxiliary processes: Input/output error": the main process got the SIGKILL and the unit restarted, but systemd's walk of the unit's cgroup.procs as the agent exited returned EIO. Not on Docker Desktop's 6.10 kernel. The lab tests now signal the agent's process alone (`signalAgent`, `--kill-whom=main`), which is what a crash does; its workers die with it (`PR_SET_PDEATHSIG`).
- **umask.** Only the tests' temporary directories were group-writable (`t.TempDir()` makes its subdirectories 0777 less the umask); the shared helpers (`tempDir` in internal/agent and cmd/thinkpol, trusteddir's, the service tests' fake host) now chmod them 0755. The product makes its own directories with explicit modes the umask can only narrow (trusteddir and the agent's `Mkdirat` 0700, files 0600, the local API's directory 0700/0750 and socket chmod'ed), so under a root umask of 0002 it never makes a directory it then refuses: no product change.
- **Go version.** `TestTheNodeFileIsStrictJSON` now asserts that the error names a byte position, not encoding/json's count of it (Go 1.26.11 says 9, 1.27.4 says 10).

## Log
- 2026-11-14 created (orchestrator's measurements on a Linux Docker 29 host)
- 2026-11-14 backlog → in-progress, owner: agent-tp-211
