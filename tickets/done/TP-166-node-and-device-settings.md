---
id: TP-166
title: "Node and device settings: the node file and the member's toggles"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: L
needs_human: macos
depends_on: []
refs: [D4, D5, S1, docs/design/configuration.md#three-levels, docs/design/configuration.md#precedence-and-narrowing]
owner: "agent-tp-166"
branch: "tp-166-node-and-device-settings"
---

## Goal
Every setting has one designed home. An operator's settings live in one root-owned node file that `up` reads; a member's toggles on a device live in a small file the service writes through the local API. Connect-on-boot becomes a member's toggle, so the tray and the CLI can change it without root. TP-111's `device` default, TP-183's ceiling and TP-048's kill switch then build on these instead of inventing their own (TP-139 findings F1, F2, F8).

## Scope
- **The node file** ([configuration](../../docs/design/configuration.md#node-level)): one root-owned file in the state directory, 0600 in the 0700 directory, JSON. It holds operating settings only (mode, interface, link MTU, DNS upstream, and the keys TP-111, TP-183 and TP-048 add), nothing about members, no history. `up` reads it at start. Name the file and its keys, and document them in the `agent` package doc and the runbook.
- **Precedence:** flags, then env, then the node file, then defaults. The map can only narrow what the node allows.
- **Unknown keys and bad values:** `up` exits with EX_CONFIG (78) and names the key or the value. The exit-code table is TP-167's; if it hasn't landed, use 78 here and TP-167 takes it over.
- **The device settings store** ([configuration](../../docs/design/configuration.md#device-level)): a small file next to the node file, written only by the service, 0600, JSON. It replaces `rules.local`: the first start that finds `rules.local` carries its preset over and removes it, and says so in the log. A store that can't be read stops the node from starting, as `rules.local` does today.
- **Connect-on-boot as a member's toggle:** a local API call to show and set it (access: the group), stored in the device store. The service always starts at boot, and the stored toggle decides whether it connects. `service connect-on-boot` and `service install -connect-on-boot` become clients of the same setting, or are removed with a message saying what replaced them; the service definition no longer carries `THINKPOL_CONNECT_ON_BOOT`.
- **Drop-ins:** Linux systemd drop-ins are unsupported. `diag` reports any `thinkpol.service.d/*.conf` it finds (a new field, following the JSON convention of TP-168).
- docs/design/configuration.md and the `agent`, `service` and `localapi` package docs updated with what was built, in the same branch.

## Out of scope
- The kill switch, allow-LAN and pause toggles themselves: TP-048 adds them to the device store this ticket builds.
- The capability ceiling: TP-183 adds it to the node file.
- Showing a setting's effective value and its source, per-space settings, a network-level minimum: open questions in docs/design/configuration.md.
- Node groups: a proposal (TP-035).

## Acceptance
- [x] unit tests: the node file and the device store are JSON; parser cases (invalid JSON, a duplicate key, an unknown key, a wrong type or bad value, an empty file) and precedence (flag over env over file over default), each case a table row
- [x] unit tests: an unknown key or a bad value makes `up` exit 78 and the message names it
- [x] unit test: a state directory with `rules.local` and no device store starts with the same preset, the store written 0600, `rules.local` gone
- [x] lab (Linux): a node started with only a node file runs with its settings; the same key given as env or flag wins over it (`thinkpol status` shows the result)
- [x] lab (Linux): `alice`, in the group, sets connect-on-boot through the CLI without root; after a service restart that counts as a boot, the node connects or stays down as she set it
- [x] lab (Linux): a drop-in under `thinkpol.service.d/` appears in `diag`
- [ ] macOS device checklist: a member of the group (not root) turns connect-on-boot on with the CLI; after a reboot the node connects; off, and after a reboot it stays down (results recorded in Notes)
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07 (findings F1, F2, F8; verdicts in docs/design/api-overview.md "Verdicts").
- Owner decisions (2026-11-07): three levels; node file root-owned 0600 in a 0700 directory, operating settings only; precedence flags > env > file > defaults; the map only narrows; device toggles through the local API by a member of the access group, stored next to the node file, replacing `rules.local`; connect-on-boot a member's toggle; JSON for both files (owner, 2026-11-07); drop-ins unsupported, reported by `diag`.
- TP-111 and TP-048 depend on this ticket. TP-167's F20 item (`rules.local` written 0600) is moot if this ticket lands first.
- Which settings take effect at once and which at the next start is to be decided per setting; record each decision in docs/design/configuration.md "When a change takes effect".
- Built (agent-tp-166): the node file is `node.json`, the device file `device.json`, both in the state directory; keys and defaults in docs/design/configuration.md. The service runs `thinkpol up -service`; connect-on-boot is `thinkpol connect-on-boot [on|off]` (local API `SetConnectOnBoot`, the group). `service connect-on-boot` and `service install -connect-on-boot` are refused with a message naming the new command. An install over an old definition says connect-on-boot moved and is off: an old "on" is not carried over (the owner turns it on again with the new command).

### macOS device checklist (owner, a later Mac session)

A Mac with this branch's `thinkpol` installed as a service (`sudo thinkpol service install -user <you>`), the node provisioned, and you (not root) in the `thinkpol` group (log out and in after the install).

1. Do: `thinkpol connect-on-boot`. Expect: `connect-on-boot: off`.
2. Do: `thinkpol connect-on-boot on` (no sudo). Expect: the status, with `connect-on-boot: on`; `sudo cat /Library/LaunchDaemons/org.thinkpol.agent.plist` unchanged (`up`, `-service`, no `EnvironmentVariables`).
3. Do: `sudo ls -l /private/var/lib/thinkpol/device.json`. Expect: `-rw-------  root`.
4. Do: reboot, log in, `thinkpol status`. Expect: `state: connected` without running `thinkpol connect`.
5. Do: `thinkpol connect-on-boot off` (no sudo), reboot, log in, `thinkpol status`. Expect: `state: disconnected`, `connect-on-boot: off`.
6. Do: `thinkpol service connect-on-boot on`. Expect: exit 1, "connect-on-boot is the device's setting now … thinkpol connect-on-boot [on|off]".
7. Record the outputs of steps 2, 4 and 5 here, under "macOS results".

## Review findings
- [x] R1.1 (should-fix) an old service definition run by the new binary connects at every start (nothing reads THINKPOL_CONNECT_ON_BOOT, the old definition runs `up` without -service, -connect defaults to true): `up` refuses to start when THINKPOL_CONNECT_ON_BOOT is in its environment, a ConfigError (exit 78) telling the operator to run `thinkpol service install`; unit row
- [x] R1.2 (should-fix, owner's decision) node.json must be root-owned 0600; it is read with private=false, so 0644/0640 and a non-root owner are accepted: enforce it with a message about settings, not keys; rows for 0644 and a non-root owner; fix the NodeFile comment that says the whole directory is 0600
- [x] R1.3 (should-fix) the same kind of fault exits 1 or 78: LoadConfig's parse error (THINKPOL_LINK_MTU=abc, THINKPOL_DNS=yes) and Prepare's "a device that starts disconnected needs the local API" are plain errors: make both ConfigErrors; rows
- [x] R1.4 (should-fix) diag's drop-in report misses part of systemd's search path (system.control, transient, generator*, system.attached, the type-level service.d/): add them in systemd's order; rows for system.control and service.d; dedupe only on a successful EvalSymlinks; rename `real`
- [x] R1.5 (should-fix, small) checkJSONKeys accepts null for a key, which reads as the default: refuse it naming the key; rows for node.json and device.json
- [x] R1.6 (should-fix, small) SetRulePreset holds settingsMu while it waits on the unbuffered rulesRequests channel, which run() reads only after taking settingsMu: copy under the lock, unlock, then select; test if practical
- [x] R1.7 (nits) carryLocalRules writes device.json on a server; NodeSettings' doc misses -api-group; definition_test.go comment names a closed ticket; `thinkpol connect-on-boot` on a server prints "off" instead of server_mode; installed(): a hand-edited old unit with THINKPOL_CONNECT_ON_BOOT also gets the "changed by hand" warning; configuration.md: an older binary refuses a device.json with unknown keys, and an old definition's connect-on-boot "on" is not carried over on install

## Log
- 2026-11-07 created in backlog
- 2026-11-07 file format is JSON for both files (owner)
- 2026-11-07 notes: the ceiling is TP-183 now (split from TP-111, owner's MVP cut)
- 2026-11-07 parser box rewritten for JSON (owner signed off the acceptance with this correction)
- 2026-11-07 backlog → in-progress, owner: agent-tp-166
- 2026-11-07 built (44c313d, a stopped agent's WIP, verified and kept): node.json (agent.NodeFile, ApplyNodeFile: flag > env > file > default; strict JSON, decodeSettings), device.json (agent.DeviceFile: connect_on_boot, rule_preset, rules; rules.local carried over at start and removed), local API SetConnectOnBoot (the group) and `thinkpol connect-on-boot`, the service runs `up -service` without THINKPOL_CONNECT_ON_BOOT, `service connect-on-boot` and `service install -connect-on-boot` refused naming the replacement, a bad configuration exits 78 (agent.ConfigError), diag's `service_drop_ins` (service.HostDropIns)
- 2026-11-07 added: lab TestTheNodeFileSetsUp, alice's connect-on-boot (on, off) across reboots and a drop-in in diag in TestServiceUnderSystemd, device.json 0600 in TestLocalAPI; unit TestDropInsAreListed, a member's and a stranger's SetConnectOnBoot in TestCallersAreCheckedByTheirCredentials, the rule's unescaped arrow in TestTheDeviceFileReadsBackWhatIsWritten; docs: configuration.md (files, keys, precedence details, when a change takes effect), agent/service/localapi package docs, the runbook, a dated note on the two API overview snapshots
- 2026-11-07 mutations, each killed: duplicate-key check off, exact-key check off, empty file accepted (TestTheNodeFileIsStrictJSON, TestSettingsKeysAreCheckedAtEveryDepth, TestTheDeviceFileIsStrictJSON); env or flag ignored in ApplyNodeFile (TestNodeSettingsPrecedence); node value check off, no exit 78 (TestUpRefusesABadNodeFile); rules.local not removed, not read, device.json 0644 (TestRulesLocalIsCarriedOverIntoTheDeviceFile); arrow escaped (TestTheDeviceFileReadsBackWhatIsWritten); onBoot ignored, connect-on-boot not stored (TestConnectOnBootIsTheDevicesToggle); drop-in dedupe off, any suffix, unreadable hidden (TestDropInsAreListed); diag without drop-ins (TestTheHostPartsAreRoots); unit keeps the variable (TestTheSystemdUnitRunsTheAgentAndRestartsIt); old definition not told (TestInstallOverAnOldDefinitionSaysWhereConnectOnBootWent); SetConnectOnBoot left out of the group's calls (TestCallersAreCheckedByTheirCredentials); status without connect-on-boot (TestTheCLIControlsTheNode); `service install -connect-on-boot` accepted (TestTheServicesConnectOnBootSaysWhatReplacedIt); lab: env ignored (TestTheNodeFileSetsUp: file and env both 1228), boot ignoring the stored toggle (TestServiceUnderSystemd failed; its failing line wasn't captured)
- 2026-11-07 lab, targeted, on 4892e9f's tree: TestTheNodeFileSetsUp, TestServiceUnderSystemd, TestLocalAPI pass
- 2026-11-07 merged origin/rewrite (TP-130) at cef3dc7; `make lint` and `make test` green there; full `make lab-test` passes on 1628035 (code as cef3dc7): lab, lab/censor, lab/ip, lab/prototypes/reality ok, every package's lab gotest PASS (an earlier full run was stopped while it waited for the lock, its leftovers removed)
- 2026-11-07 not verified: the macOS device checklist (Notes; the owner's, in a later Mac session); launchd's plist runs `up -service` only as files and fake launchctl here
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-07 has-errors → in-progress, owner: agent-tp-166 (round 1 fixes)
- 2026-11-07 round 1 fixed: R1.1 `up` refuses THINKPOL_CONNECT_ON_BOOT in its environment (agent.CheckEnvironment, exit 78); R1.2 node.json must be the service's user's (root) and 0600 (checkNodeFileOwnerMode; a non-root agent can't read a root 0600 file, so its own uid stands in for root); R1.3 LoadConfig's parse error and Prepare's disconnected-device check are ConfigErrors; R1.4 diag lists drop-ins on systemd's whole system unit search path in its order, thinkpol.service.d then service.d per directory, dedupe only on a resolved path, `real` renamed; R1.5 a null value is refused naming the key; R1.6 SetRulePreset stores under settingsMu, then waits on the data plane under its own presetMu; R1.7 no carry-over on a server, -api-group in NodeSettings' doc, closed ticket id dropped, `connect-on-boot` shown on a server is server_mode (Client.ConnectOnBoot), a hand-edited old definition also gets the changed-by-hand warning (frozen old renders in olddefinition.go), configuration.md: rollback needs device.json removed, an old "on" is not carried over
- 2026-11-07 tests added: TestUpRefusesABadEnvironment (old definition's variable, MTU abc, MTU 100, DNS yes, device disconnected without the local API), TestTheNodeFileIsRootsAlone (0644, 0640, 0604; owner rows), null rows in TestTheNodeFileIsStrictJSON and TestTheDeviceFileIsStrictJSON, system.control, service.d and two unresolvable directories in TestDropInsAreListed, TestARulePresetSetBeforeTheNodeRunsIsTaken, a server row in TestRulesLocalIsCarriedOverIntoTheDeviceFile, ConnectOnBoot rows in TestTheCLIControlsTheNode, as-written and hand-edited rows in TestInstallOverAnOldDefinitionSaysWhereConnectOnBootWent
- 2026-11-07 mutations, each killed: CheckEnvironment off, LoadConfig's error plain, Prepare's error plain (TestUpRefusesABadEnvironment); mode check off, owner check off, ReadNodeFile skipping the check (TestTheNodeFileIsRootsAlone); system.control left out, service.d left out, dedupe on a failed resolve (TestDropInsAreListed); null accepted (TestTheNodeFileIsStrictJSON, TestTheDeviceFileIsStrictJSON); settingsMu held across the send (TestARulePresetSetBeforeTheNodeRunsIsTaken: deadline exceeded); server carries rules.local (TestRulesLocalIsCarriedOverIntoTheDeviceFile); server check off in ConnectOnBoot (TestTheCLIControlsTheNode); hand-edited old not warned (TestInstallOverAnOldDefinitionSaysWhereConnectOnBootWent)
- 2026-11-07 merged origin/rewrite (TP-119, TP-146) at 5cf6cdf; `make lint` and `make test` green there
- 2026-11-07 lab, targeted, on 5cf6cdf: TestTheNodeFileSetsUp, TestServiceUnderSystemd, TestLocalAPI pass; full `make lab-test` passed on 54dce53, then rewrite moved (TP-132)
- 2026-11-07 merged origin/rewrite (TP-132) at 9220441: conflicts in install.go, service/doc.go, the runbook resolved keeping both sides; TP-132's test called the removed Installer.ConnectOnBoot, now in.installed(); `make lint`, `make test` green; full `make lab-test` passes on 9220441: lab, lab/censor, lab/ip, lab/labctl, lab/prototypes/reality ok, gotest ok, 37 packages
- 2026-11-07 not verified: the node.json owner refusal as root on a real host (the owner rule is a unit row; the lab writes node.json as root 0600); the frozen old definitions are copied from rewrite's pre-TP-166 renderers by hand (no test against the old code); the macOS device checklist stays the owner's
- 2026-11-07 note: the brief asked for has-errors → review; the README allows has-errors → in-progress → review, so the ticket went that way
- 2026-11-07 in-progress → review
- 2026-11-07 review → done, merged into rewrite (round 1: go-paranoid, go-style, pocket-torvalds, same-family second Opus; R1.1–R1.7 fixed; delta check: merge; the macOS device checklist box stays open for the owner's next Mac session)
