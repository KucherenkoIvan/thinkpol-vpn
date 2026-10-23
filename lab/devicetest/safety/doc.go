// Package safety is the device-test harness's frozen core (lab/devicetest):
// the only code that runs as root on the owner's Mac, and what puts the
// Mac back after a run.
//
// # Frozen
//
// FROZEN pins the sha256 of every file in this directory, and
// TestTheSafetyCoreIsFrozen fails when one differs. A change to this
// package, a new kind of action included, needs a ticket of its own (no
// plan changes in it) and the owner's approval, every time; its real
// tests pass in the lab and one device self-test run (`devicetest
// selftest`) passes before it merges. The test's failure prints the new
// FROZEN, so the pin moves only in a reviewed diff. The core reads pf with
// package firewall's readers and directories with trusteddir: a change
// there reaches the core without moving the pin, and its review says so.
//
// # What it guarantees
//
//   - Nothing changes on the host without a restore plan for it
//     ([Engine.Do]): the baseline is taken, the dead-man is armed, and the
//     change's undo is written to the journal and synced before the change
//     is made; any of them missing, the change is refused
//     ([ErrNoRestorePlan]). A change that fails is undone at once.
//   - Changes are typed actions ([Action]): a closed set of kinds
//     ([Decode]), each with a precondition that refuses it when its undo
//     couldn't put the host back, and an undo that checks first whether
//     the change is there, so it is safe to repeat. Root reads are
//     listings of the shapes [RootRead] allows; nothing else runs as root.
//   - A normal end, or Ctrl-C (any number of them), undoes every change,
//     newest first, then compares the host with its baseline: CLEAN, LEFT
//     (each item with what to do next) or REBOOT ([Result]). The helper
//     ignores the terminal's signals; the user side asks it to restore.
//   - A closed terminal, or the user side killed: the helper's input ends
//     and it restores at once.
//   - The helper crashed, killed or hung: the dead-man ([Deadman]), a
//     process of its own in a session of its own, restores from the
//     journal when the helper is gone (an unreaped zombie counts as gone),
//     or past the plan's budget when no restore is making progress (the
//     heartbeat changes only when a restore makes progress, never on a
//     timer), or at the cap whatever the heartbeat says. Time is Go's
//     monotonic clock; the heartbeat's age is when its content last
//     changed, so setting the wall clock moves nothing.
//   - Everything killed, or the power lost: the journal and the active
//     pointer stay in root's state directory, every later run is refused
//     until `devicetest restore` replays the journal. A volatile change
//     (kernel state: a capture, pf's rules) of an earlier boot is gone with
//     that boot and isn't touched, its pid someone else's now; a
//     persistent one is undone.
//
// # The pieces
//
// The journal ([Journal]) is JSON lines in root's run directory, one line
// per state change (intent, applied, undone, undo-failed,
// gone-with-reboot), each synced, stamped with the boot session and the
// wall and monotonic clocks; a line cut by a crash is ignored. The helper
// ([Helper]) is started by the launch script ([RootCommand]): sudo runs one
// fixed shell script that copies the binary into a fresh root-owned 0700
// directory, checks the copy's sha256 against the one the user side
// computed, and runs the copy ([CheckRootCopy]), so a file the user can
// write never runs as root. It speaks one JSON line per request and answer
// ([Request], [Response]) on its stdin and stdout. Root writes the evidence
// ([Evidence]) on the owner's behalf: the folder opened once and checked as
// the owner's, every file made relative to it, never through a symlink nor
// over an existing file, and handed to the owner; root never deletes
// anything there.
//
// Snapshots ([Host.Snapshot]) read the host's surfaces, raw output to the
// evidence and normalised lines to the run directory. On macOS they are
// the phase-end runbook's pfcheck: the main rules, nat, the skipped
// interfaces (`(skip)` lines, lo0 included), Apple's AirDrop and
// Application Firewall anchors and thinkpol's guard anchor; its pfrestore
// (pf's Status); and `scutil --dns` without its reach lines, a difference
// there reported but not counted as left over. `-s References` and the
// list of anchors are recorded only. Before the comparison the restore
// settles in the runbook's order: no thinkpol process (up to 60 s), the
// guard's pf reference released (up to 30 s), and only then pf turned
// back on if the baseline had it on. It never turns pf off, never flushes
// anything, never writes /etc/pf.conf, DNS, routes or a Setup: key.
//
// The actions: a file of the run's own in its run directory (the
// self-test's harmless change), a capture (a tcpdump the helper runs and
// reads, the pcap written record by record and watched for the
// self-test's markers, lab/pcap's reader), and on macOS pf's main
// ruleset loaded as one line followed by the stock rules (TP-096's `set
// skip on lo`): refused unless the rules loaded now are the baseline's and
// those are what /etc/pf.conf loads (`pfctl -n -v -f`); undone by
// loading /etc/pf.conf, once more if pf still differs, then REBOOT.
//
// # Tests
//
// As the user on any machine (make test), with real processes, kill -9 and
// fsync, and surfaces of the test's (a file read with cat: the host's pf
// is never read): the journal replayed after a kill -9 of the process
// writing it, a cut last line, a power loss (another boot session), the
// refusals, the dead-man against a killed helper, a stop file, no
// heartbeat, a fresh one (the cap) and one going stale, the helper's
// restore when its input ends and after SIGINT and SIGHUP, the dead-man's
// after a kill -9, an unfinished run blocking the next until restored,
// the evidence writer against symlinks, the root-read allowlist, the live
// reader on a capture recorded in the lab, and the macOS normalisers on
// recorded listings. As root in a lab node (make lab-test): the launch
// script's root copy and its hash check, and a real tcpdump applied and
// undone through the journal. What only the Mac shows (the pf action, the
// macOS surfaces against a real pfctl, sudo) is the owner's device
// checklist (TP-082's Notes).
package safety
