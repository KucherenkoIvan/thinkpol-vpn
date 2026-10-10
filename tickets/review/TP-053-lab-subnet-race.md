---
id: TP-053
title: "Lab subnet allocation survives a vanishing network"
milestone: M0
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-002]
refs: [DESIGN#censor-lab]
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
- **Fix** (`lab/subnets.go`): `usedSubnets` still lists and inspects every daemon network in one call each; when the inspect fails with "not found" (`Error response from daemon: network x not found`, or `No such network: x` from newer CLIs, matched by `isNotFound` on the CLI's stderr and a non-zero exit only, so a missing `docker` binary doesn't count), it inspects the listed networks one by one and skips the ones that are gone. Any other error still fails allocation. The seam is `usedSubnetsVia(ctx, dockerFunc)`.
- **Tests:** `TestUsedSubnetsSkipsNetworksRemovedAfterTheList` (unit, a fake CLI that drops a network after `network ls`, both message forms, and the freed /24 is allocatable again), `TestUsedSubnetsFailsOnOtherInspectErrors`, `TestIsNotFound`; `TestUsedSubnetsSurvivesANetworkRemovedMidway` (lab tag: two throwaway networks of the test's own, `tplab-subnet-race-{gone,kept}-<random>`, Docker-allocated subnets, the `gone` one removed right after the real `docker network ls`; the kept subnet is reported, the gone one isn't). Both tests fail without the fix, the lab one with exactly the reported error (`network inspect ... exit 1: ... network <id> not found`).
- **Other read paths, checked:** `labProjects` and `downProject`'s listings are single `ps -a` / `network ls` calls that read labels from the list itself, with no follow-up inspect, so nothing can vanish in between. `Lab.inspect` reads only the lab's own containers and networks; those vanishing means the lab is broken, so it keeps failing loudly. `prepare`'s `image inspect` already treats any failure as "build the image". `Node.Exec`/`GoTest`/`ExportFS` act on the lab's own containers. So the subnet listing was the only list-then-inspect over other daemon users' resources.
- `make lint`, `make test` green; `make lab-test` green (~1.5 min, 10 in-node packages).

## Log
- 2026-10-11 created in in-progress — owner: agent-lab-race, branch: tp-053-lab-subnet-race (bug from TP-009's lab-test run)
- 2026-10-11 in-progress → review — fix in 8cffb99; make lint, make test, make lab-test green
