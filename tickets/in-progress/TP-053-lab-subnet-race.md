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
- [ ] a network vanishing between list and inspect doesn't abort allocation; "not found" means "no longer occupying a subnet", and other inspect errors still fail it
- [ ] tested with an injected list/inspect seam (unit test) and with a real throwaway network of the test's own, deleted mid-allocation (lab test)
- [ ] any other transient Docker "not found" in the harness's read paths handled the same way, or noted here as not applicable
- [ ] `make lint`, `make test`, `make lab-test` green

## Notes

## Log
- 2026-10-11 created in in-progress — owner: agent-lab-race, branch: tp-053-lab-subnet-race (bug from TP-009's lab-test run)
