// Package safety is the device-test harness's frozen core (lab/devicetest):
// the code that runs as root on the owner's Mac, and what puts the Mac
// back after a run. Its root processes, the only ones the harness has, are
// devicetest-root's three modes: the helper, its dead-man, and
// root-restore.
//
// # Frozen
//
// FROZEN pins the sha256 of every file in this directory and the set of
// packages the core imports; TestTheSafetyCoreIsFrozen fails when either
// differs, and prints the new FROZEN. A change to this package (a new kind
// of change or a new dependency included) needs a ticket of its own, with
// no plan changes in it, and the owner's approval, every time; its real
// tests pass in the lab and one device self-test run (`devicetest
// selftest`) passes before it merges. The core reads pf with package
// firewall's readers and directories with trusteddir: a change there
// reaches the core without moving the pin, and its review says so.
//
// # What it guarantees
//
//   - Nothing changes on the host without a restore plan for it: the
//     baseline is taken, the dead-man is armed, and the change's undo is
//     written to the journal and synced before the change is made; any of
//     them missing, the change is refused. A change that fails is undone
//     at once. Changes are typed (a closed set of kinds, Spec), each with
//     a precondition that refuses it when its undo couldn't put the host
//     back, and an undo that checks first whether the change is there, so
//     it is safe to repeat. Root reads are listings of the shapes RootRead
//     allows; nothing else runs as root.
//   - A normal end, or Ctrl-C (any number of them), undoes every change,
//     newest first, then compares the host, in a fresh snapshot, with its
//     baseline: CLEAN, LEFT (each item with what to do next) or REBOOT
//     (Result). The helper ignores the terminal's signals; the user side
//     asks it to restore.
//   - A closed terminal, or the user side killed: the helper's input ends
//     and it restores at once.
//   - The helper crashed, killed or hung: the dead-man, a process in a
//     session of its own, restores from the journal when the helper is
//     gone (watched by pid and start time; an unreaped zombie is gone),
//     past the plan's budget when no restore is making progress (the
//     heartbeat changes only when a restore makes progress, never on a
//     timer), or at its limit, budget + 10 min, whatever the heartbeat
//     says. Its budget counts the larger of the monotonic and wall-clock
//     time since it started: setting the clock back can't hold it, and a
//     Mac asleep, whose monotonic clock stops, counts as time passed. A
//     stop file disarms it; only a file actually there counts, never an
//     error reading the directory.
//   - Everything killed, or the power lost: the journal and the active
//     pointer stay in root's state directory, and every later run is
//     refused until `devicetest restore` replays the journal. A volatile
//     change (kernel state: a capture, pf's rules) of an earlier boot is
//     gone with that boot and isn't touched, its pid someone else's now; a
//     persistent one is undone.
//   - A result that isn't CLEAN leaves the run pending (a "left" pointer):
//     no run starts until `devicetest restore` compares the host with that
//     run's baseline again and finds it clean. A restore with nothing
//     pending says NOTHING-TO-RESTORE, never CLEAN.
//
// # The pieces
//
// The journal is JSON lines in root's run directory, one line per state
// change (intent, applied, undone, undo-failed, gone-with-reboot), each
// synced, stamped with the boot session and the wall and monotonic clocks.
// Only its last line can be cut short by a crash, and reading it back cuts
// that off before anything is appended; a complete line that doesn't
// parse is corruption. The active pointer is written only after the
// journal's header is synced. The state directory keeps the newest 10
// runs' directories (the owner's choice); older ones are pruned, file by
// file, when a run starts, never one pending a restore, and never the
// evidence.
//
// The launch script (RootCommand) is the one command sudo runs: it checks
// the temporary directory is a sticky directory of root's, copies
// devicetest-root into a fresh 0700 directory of root's there, checks the
// copy's sha256 against the one the user side computed, and runs the copy,
// so a file the user can write never runs as root. The helper speaks one
// JSON line per request and answer (Request, Response). Root writes the
// evidence on the owner's behalf: the folder opened once and checked as
// the owner's own (trusteddir.OpenOwnedBy), every file made relative to
// it, never through a symlink nor over an existing file, and handed to
// the owner; root never deletes anything there.
//
// Snapshots read the host's surfaces, the raw output to the evidence and
// the normalised lines to the run directory, under names only the core
// chooses, each written once: the baseline is never replaced, and a later
// restore's snapshot takes a name of its own. On macOS they compare every
// line of pf's main rules, nat rules, skipped interfaces (lo0 included),
// Apple's AirDrop and Application Firewall anchors and thinkpol's guard
// anchor, and pf's state; `scutil --dns` without its reach lines is
// compared too, a difference there reported, not counted as left over. pf's
// references and its list of anchors are recorded only. Before the
// comparison the restore waits, in this order, for no thinkpol process
// (up to 60 s; an agent releases its pf reference last, and that can turn
// pf off), then for the guard's record to hold no reference of this boot
// (up to 30 s), and only then turns pf back on if the baseline had it on
// and it is off (`pfctl -e`, checked): the one change a restore makes that
// no journal entry names, since it puts back what the baseline recorded.
// It never turns pf off, never flushes anything, never writes
// /etc/pf.conf, DNS, routes or a Setup: key.
//
// The changes: a file of the run's own in its run directory (the
// self-test's harmless change); a capture, a tcpdump (promiscuous mode off,
// its filter after `--`, never one that looks like an option) whose pid
// and start time are journaled the moment it runs, which the helper
// reads, writing the pcap record by record and watching for the self-test's
// markers (lab/pcap's reader), and which only the restore ends; and, on
// macOS, `set skip on <name>` loaded before the stock rules, refused unless the rules loaded now are the baseline's and what
// /etc/pf.conf loads (`pfctl -n -v -f`) and nothing is skipped already,
// undone by loading /etc/pf.conf, once more if pf still differs, then
// REBOOT.
//
// Its tests drive real processes, kill -9, fsync and, in lab nodes, real
// root and tcpdump; what only a Mac shows is on the owner's device
// checklist.
package safety
