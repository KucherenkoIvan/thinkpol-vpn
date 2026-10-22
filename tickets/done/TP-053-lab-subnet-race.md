---
id: TP-053
title: "Lab subnet allocation survives a vanishing network"
milestone: M0
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-002]
refs: [docs/design/lab.md#censor-lab]
owner: "agent-lab-race"
branch: "tp-053-lab-subnet-race"
---

## Goal
`make lab-test` doesn't abort because some other checkout or project removed a Docker network while this lab was allocating subnets. Today allocation lists every daemon network and then inspects them all in one call; a network removed in between makes the inspect fail and the whole run abort (seen once during TP-009's full `make lab-test`, in the per-package phase).

## Scope
- Subnet allocation (`lab/subnets.go`, from TP-002): a network that is "not found" when inspected no longer occupies a subnet and is skipped; the rest are still read and checked.
- Every other read path of the harness that lists daemon resources and then reads them is checked for the same race and handled the same way. Paths that only read the lab's own containers and networks keep failing loudly: those vanishing means the lab is broken.

## Out of scope
Anything that writes (create, tear-down), and the allocation's overlap retry, which already covers networks created after the list.

## Acceptance
- [x] a network vanishing between list and inspect doesn't abort allocation; "not found" means "no longer occupying a subnet", and other inspect errors still fail it
- [x] tested with an injected list/inspect seam (unit test) and with a real throwaway network of the test's own, deleted mid-allocation (lab test)
- [x] any other transient Docker "not found" in the harness's read paths handled the same way, or noted here as not applicable
- [x] `make lint`, `make test`, `make lab-test` green

## Notes
- **Fix** (`lab/subnets.go`): `usedSubnets` lists every daemon network (`network ls -q --no-trunc`, full ids) and inspects them in one call; when that inspect fails with a "not found" naming one of the listed ids, it inspects them one by one and skips each one whose own failure names its id (`network <id> not found` from the daemon, `No such network: <id>` / `No such object: <id>` from other CLIs, matched on stderr after a non-zero exit, with an id boundary so a prefix doesn't count). Anything else fails: connect errors, a missing CLI, every listed network unreadable (the daemon's own networks always exist, so that's a sick daemon, not a race), and a subnet that doesn't parse. The seam is `usedSubnetsVia(ctx, dockerFunc)`.
- **Tests:** `TestUsedSubnetsSkipsNetworksRemovedAfterTheList` (unit, a fake CLI that drops a network after `network ls`, both message forms, and the freed /24 is allocatable again), `TestUsedSubnetsFailsClosed` (daemon unreachable, socket gone, `command not found`, permission denied, an unparseable subnet, every listed network gone), `TestNetworkNotFound` (anchoring, including the connect-error texts); `TestUsedSubnetsSurvivesANetworkRemovedMidway` (lab tag: two throwaway networks of the test's own, `tplab-subnet-race-{gone,kept}-<random>`, cleanup by name registered before each create, Docker-allocated subnets, the `gone` one removed right after the real `docker network ls`; the kept subnet is reported, the gone one isn't). Both race tests fail without the fix, the lab one with exactly the reported error (`network inspect ... exit 1: ... network <id> not found`).
- **Other read paths, checked:** `labProjects` and `downProject`'s listings are single `ps -a` / `network ls` calls that read labels from the list itself, with no follow-up inspect, so nothing can vanish in between. `Lab.inspect` reads only the lab's own containers and networks; those vanishing means the lab is broken, so it keeps failing loudly. `prepare`'s `image inspect` already treats any failure as "build the image". `Node.Exec`/`GoTest`/`ExportFS` act on the lab's own containers. So the subnet listing was the only list-then-inspect over other daemon users' resources.
- `make lint`, `make test` green; `make lab-test` green (~1.5 min, 10 in-node packages). Again after the review fixes.

## Review findings
Review by the coordinator, 2026-10-11.

- [x] R1 `isNotFound` is too loose: a daemon restart ("dial unix …: no such file or directory") or "command not found" reads as "every network vanished" and yields an empty used list. Anchor matches to the object (`network <id> not found`, `no such network: <id>`, `no such object: <id>`), require the message to name that id in the per-network fallback, and fail closed if ls listed ids but none could be read. Unit test with the connect-error text.
- [x] R2 `network ls -q --no-trunc` (full ids; no name/prefix confusion).
- [x] R3 Unparseable subnets fail loudly instead of being dropped silently.
- [x] R4 Lab test: register the cleanup (by name) before creating the network.

## Log
- 2026-10-11 created in in-progress — owner: agent-lab-race, branch: tp-053-lab-subnet-race (bug from TP-009's lab-test run)
- 2026-10-11 in-progress → review — fix in 77266f2; make lint, make test, make lab-test green
- 2026-10-11 review → has-errors — review findings R1–R4, see Review findings
- 2026-10-11 has-errors → in-progress — owner: agent-lab-race, fixing the review findings
- 2026-10-11 in-progress → review — review findings R1–R4 fixed (045c14d); make lint, make test, make lab-test green
- 2026-10-11 review → done — merged into rewrite
