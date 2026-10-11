---
id: TP-012
title: "M0 acceptance in the lab"
milestone: M0
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-002, TP-011]
refs: [C1, DESIGN#milestones]
owner: "agent-tp-012"
branch: "tp-012-m0-acceptance"
---

## Goal
M0's "done when" as automated lab tests.

## Scope
- `device-a` ↔ `server-1` ping over overlay IPv4 and IPv6.
- `device-a` ↔ `device-b` through `server-1` as relay, IPv4 and IPv6.
- Capture at the router contains no WireGuard message signatures (type byte 1–4 followed by three zero bytes, 148/92-byte handshakes).

## Acceptance
- [x] `make lab-test` is green with these tests — `TestM0` (lab/m0_test.go) runs twice, `underlay=ipv4` (lab/maps/m0.yaml as is) and `underlay=ipv6` (m0.yaml minus the IPv4 endpoint), each with keys and map made by `thinkpol dev keygen`/`dev map build` on the `internet` node and `thinkpol up` on server-1, device-a, device-b. Subtests, all passing in both:
  - `server-1 runs the space in its own worker`: one `thinkpol worker`, child of `thinkpol up`, own net/user/pid/mnt namespaces, non-root uid; server-1's overlay addresses only in its netns. "worker 105 (uid 2000300000) under supervisor 91, own net/user/pid/mnt namespaces; overlay addresses only in its namespace"
  - `direct: devices and server-1`: device-a and device-b ping 100.64.0.1 and `<ula>::1`; server-1 (from the worker's netns) pings both devices over both families. Burst of 20 × 1200-byte pings device-a → server-1, at server-1: "device-a: 20 in, 20 out" and nothing with device-b
  - `relayed: device to device through server-1`: device-a ↔ device-b over overlay IPv4 and IPv6 both ways. Relay proof by capture at server-1 for a burst device-a → device-b: "ping 100.64.0.3 from device-a, at server-1: device-a: 20 in, 20 out; device-b: 20 in, 20 out" (same for `<ula>::3`)
  - `no traffic between the devices but through server-1`: each device's own capture of the whole run: "device-a: 105 datagrams sent to server-1 at 172.16.234.3; 0 unicast packets to or from device-b's addresses [… link-local included]"
  - `no WireGuard on the wire at the router (C1)`: "router: 686 udp datagrams over the whole run (686 of the data plane, from the first handshake on, over IPv4; 480 of them burst-sized), 0 with a WireGuard header or message" (678 over IPv6 in the same run)
  - the classifier: `TestCaptureFlagsRawWireGuard` (kernel WireGuard device-a ↔ server-1 through the same router capture): "router: 8 raw WireGuard datagrams (by type: map[1:1 2:1 4:6]), all flagged"; `TestLooksLikeWireGuard` (unit, `make test`) covers sizes, types and reserved bytes
  - mutations seen to fail: a UDP datagram sent straight from device-a to device-b fails the no-direct subtest, a 148-byte `01 00 00 00 …` datagram sent across the router fails C1 (temporary edit, not committed)

## Notes
- **What "directly" means in M0.** Devices have no endpoints (TP-004 S4), so device ↔ device traffic always goes through a server; direct device paths are after the MVP (DESIGN.md "Milestones"). The direct leg is device ↔ server-1, the relayed one device-a ↔ device-b through server-1. DESIGN.md's M0 "done when" said "device ↔ device, directly and via a relay": reworded to "directly (device ↔ server) and device ↔ device via a relay", linking lab/M0.md.
- **"Over IPv4 and IPv6"** is tested on both layers: overlay pings over 100.64/10 and the space's ULA, and the underlay once over IPv4 and once IPv6-only (all data-plane datagrams at the router checked to be of that family). Before starting, the test reads device-a's opened section with `dev map inspect` to confirm one link (to server-1, at the underlay under test first) and server-1 as device-b's only first hop.
- **Relay proof.** At the router device-a ↔ device-b traffic wouldn't show (both devices are on the `devices` bridge), so the no-direct proof uses each device's own capture (multicast ND/RS excluded: it reaches every node), and the relay proof counts ≥ 1200-byte datagrams at server-1's underlay (nothing else the data plane sends is that large).
- **Classifier** lives in package `lab` (`lab.LooksLikeWireGuard`: type 1–4, three zero bytes, 148/92/64 bytes or ≥ 32 in 16-byte steps; `lab.WireGuardHeader`: the header alone). C1 asserts the looser header check on every UDP payload. udp's own `looksLikeWireGuard` (TP-005, test file) is unchanged. `TestCaptureFlagsRawWireGuard` needs WireGuard in the Docker VM's kernel (it creates `wg0` inside two lab containers only).
- **Need to know** is covered where the map is made, not repeated here: `TestSectionsHoldOnlyWhatTheirNodeNeeds` (internal/devmap), `TestOpenOnlyOwnSection` (internal/netmap), `TestDevMapLabWorkflow` (cmd/thinkpol); `TestUpRunsTheM0Space` checks each node's state directory. lab/M0.md lists them.
- **Shared setup** with `TestUpRunsTheM0Space`: `m0Space` got a `spec` field (the IPv6 variant builds from `/tmp/m0/m0-ipv6.yaml`); `newM0Space`, `install`, `overlay`, `ping`, `waitLog`, `applied` are reused as they are.
- **Seen once, not ours:** the first `make lab-test` (before any change here) failed `TestSharedListenerThroughput` (internal/agent/supervisor, TP-010): "lost 0.820% at the handoff … at 100 Mbit/s, want under 0.5%", with other labs running on the same Docker VM; it passed in the next full run. A load-sensitive threshold: now gated in `make lab-perf` only (R4).
- **Review fixes (2026-10-12):**
  - R1: `Capture.Complete()` stops a capture and errors on tcpdump's "N packets dropped by kernel/interface" (parsed from the kept stderr tail; no statistics at all is an error too), on frames captured short (pcap `orig_len > incl_len`, which the decoder would otherwise skip silently) and on a stream error; a capture's clean-up calls it, so every lab test using `Capture` now fails on an incomplete one. It found a real loss: the router's whole-run capture in TestM0 dropped exactly 1 packet in both runs ("727 packets captured, 728 received by filter, 1 packet dropped by kernel"), during the MLD burst at startup. Cause: in immediate mode libpcap uses a ring with one frame per snapshot length, so `-s 0` (256 KiB) in the default 2 MiB buffer leaves about eight slots. Captures now use `-s 65600 -B 32768` (about 500 slots); no drops since, in TestM0, TestShapingCapture and TestSmoke.
  - R2: only multicast ICMPv6 and IGMP are exempt (`lab.ProtoIGMP` added); multicast UDP is direct traffic and must go to server-1's listener. Seen failing with a datagram from device-b to 224.0.0.251:5353.
  - R3: bursts compared to the replies received ("20 replies; device-a: 20 in, 20 out; device-b: 20 in, 20 out"), a lossy burst tried once more; all four Uid fields; a missing Uid line is fatal; any IPv4 UDP at the router fails the IPv6-only run (seen failing); `lab.WireGuardOffset` (a whole WireGuard message at any offset, to the payload's end) in C1 (seen failing with an initiation behind 18 bytes); the "not vacuous" floor is now the bursts' exact count, 480 burst-sized sightings at the router (2 × (2 direct × 2 + 2 relayed × 4) × 20), which every run hits exactly; the totals are 678–690 per run (single pings, handshakes, keepalives and probes are timer-dependent), so "686" was typical, not fixed. M0.md says what the asserts check.
  - R4: `make lab-perf` = `labctl gotest -perf -v -p 1 -run 'Throughput$' $(LAB_PERF_PKGS)`: `lab.AcquirePerfLock` takes `perf.lock` exclusively (every lab slot now takes it shared, except labs of the process holding it), sets `THINKPOL_LAB_PERF=1` in the node (`GoTestEach` takes extra env). `TestSharedListenerThroughput` measures once and, under perf on a miss, twice more and gates on the per-figure median; under `make lab-test` it fails only on a broken handoff (≥ 20% loss or nothing through) and logs the figures. `TestPerfLockExcludesLabSlots` (unit) checks the lock both ways. lab/README.md "Performance gates". `make lab-perf`: "paced 100 Mbit/s: 35723 sent … loss 0.000% at the handoff, 0.000% at the worker", "one way: 1241.1 Mbit/s", "echo: 348.8 Mbit/s".
  - Seen once while fixing, not ours: `TestWorkersAreSandboxed` (internal/agent/supervisor, TP-009) failed once in a full `make lab-test` with `space 0: net namespace "net:[4026534319]" shared (root's is "net:[4026534319]")`, then passed three package runs and the next full run. A worker reported in the test's own network namespace is worth a look by TP-009's owner (a pid read before the worker's unshare, or a pid reused).
- **For TP-024 (censor/RESULTS.md):** reuse `lab.LooksLikeWireGuard`/`lab.WireGuardHeader` and `TestCaptureFlagsRawWireGuard`'s kernel-WireGuard positive control; lab/M0.md is the M0 part of what RESULTS.md will summarise.

## Review findings
Review verdict: merge after these. The DESIGN.md M0 rewording is accepted by the orchestrator.

- [x] R1 `lab/capture.go`: keep tcpdump's stderr tail, parse "N packets dropped by kernel" in Stop, and fail (or expose `Dropped()` and make the M0 checks fail) when non-zero
- [x] R2 m0_test.go multicast exemption: exempt only ICMPv6 (ND/RS/MLD) and IGMP; multicast UDP falls through to the direct-traffic and "sent only to server-1" checks
- [x] R3 Nits: compare burst counts to the replies actually received (or retry a burst once) to avoid single-loss flakes; check all four Uid fields; guard a nil uid; in the IPv6-only run fail on any IPv4 UDP between lab nodes at the router; optional C1 hardening (LooksLikeWireGuard at any offset); M0.md wording matches the asserts (≥ 20, non-multicast UDP, ≥ 160 floor); confirm the "686" numbers
- [x] R4 Perf tests out of acceptance runs (decision): `TestSharedListenerThroughput`'s threshold gate behind a `make lab-perf` target (build tag or `THINKPOL_LAB_PERF=1`) that takes an exclusive host lock (normal labs take slot locks shared) and re-measures up to 3 times (median) before failing; `make lab-test` keeps a functional check of the handoff and logs the loss figure. Documented in lab/README.md and this ticket's Notes (not TP-010's)

## Log
- 2026-10-10 created in backlog
- 2026-10-11 backlog → in-progress — owner: agent-tp-012, branch: tp-012-m0-acceptance (based on tp-011-thinkpol-up while TP-011 is in review)
- 2026-10-11 in-progress → review — `TestM0` (underlay ipv4/ipv6), `TestCaptureFlagsRawWireGuard`, `TestLooksLikeWireGuard`; lab/M0.md; DESIGN.md M0 "done when" reworded (devices have no direct paths in the MVP); `make lint`, `make test`, `make lab-test` pass
- 2026-10-11 review → has-errors — review findings R1–R4
- 2026-10-11 has-errors → in-progress — owner: agent-tp-012, fixing R1–R4
- 2026-10-12 merged origin/rewrite (TP-011 done)
- 2026-10-12 in-progress → review — R1–R4 fixed; `make lint`, `make test`, `make lab-test`, `make lab-perf` pass
