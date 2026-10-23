// Package safety is the device-test harness's frozen core (lab/devicetest):
// the code that runs as root on the owner's Mac, and what puts the Mac
// back after a run. Its root processes, the only ones the harness has, are
// devicetest-root's three modes (RootMain): the helper, its dead-man, and
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
//     them missing, the change is refused. A baseline that can't read a
//     surface it compares stops the run before any change: no restore
//     could show the host equal to it. A change that fails is undone at
//     once. Changes are typed (a closed set of kinds, Spec), each with a
//     precondition that refuses it when its undo couldn't put the host
//     back, and an undo that checks first whether the change is there, so
//     it is safe to repeat. Root reads are listings of the shapes the core
//     allows; nothing else runs as root.
//   - A normal end, or Ctrl-C (any number of them), undoes every change,
//     newest first, then compares the host, in a fresh snapshot, with its
//     baseline (Result). The helper ignores the terminal's signals; the
//     user side asks it to restore.
//   - A closed terminal, or the user side killed: the helper's input ends
//     and it restores at once.
//   - The helper crashed, killed or hung: the dead-man, a process in a
//     session of its own, restores its own run from the journal when the
//     helper is gone (watched by pid and start time; an unreaped zombie is
//     gone), past the plan's budget when no restore is making progress
//     (the heartbeat changes only when a restore makes progress, a
//     snapshot after each surface it reads, never on a timer), or at its
//     limit, budget + 10 min, whatever the heartbeat says. Its budget
//     counts the larger of the monotonic and wall-clock time since it
//     started: setting the clock back can't hold it, and a Mac asleep,
//     whose monotonic clock stops, counts as time passed. A stop file
//     disarms it; only a file actually there counts, never an error
//     reading the directory.
//   - Everything killed, or the power lost: the journal and the active
//     pointer stay in root's state directory, and every later run is
//     refused until `devicetest restore` replays the journal. A volatile
//     change (kernel state: a capture, pf's rules) of an earlier boot is
//     gone with that boot and isn't touched, its pid someone else's now; a
//     persistent one is undone. The journal and the state directory are
//     synced with F_FULLFSYNC on macOS, past the drive's cache.
//   - A result that doesn't close the run leaves it pending (a "left"
//     pointer, on disk before the active one goes): no run starts until a
//     restore closes it.
//
// # Verdicts
//
// CLEAN: every change undone and the host equal to the baseline. LEFT:
// something differs or failed to undo, each item with what to do next.
// REBOOT: what loading /etc/pf.conf controls (the main rules, nat rules
// and skipped interfaces) still differs after the undo, the core's own pf
// change surviving it; pf's state, Apple's anchors and thinkpol's guard
// anchor are the system's and other apps', so a difference there is LEFT
// with what to do, and DNS is reported only. Both keep the run pending.
// NOTHING-TO-RESTORE: no run was pending, or the run didn't start (its
// result says why); nothing was compared. RESET-BY-REBOOT: a pending run
// restored in a later boot with no change of its own left in its journal
// (each undone, or gone with the boot it was made in, as every volatile
// change is) and the host still unlike the baseline: what differs is the
// new boot's. FORGOTTEN: `devicetest restore -forget RUN`, the owner
// naming a pending run in a later boot than its own, for what can't be
// proven otherwise (a journal that doesn't read back, a baseline that
// can't, a persistent change that can't be undone): it shows what the
// journal still says and how the host compares now. The last four close
// the run; only CLEAN says the host is as it was.
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
// file, when a run starts, which happens only with no run pending, and
// never the evidence.
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
// compared too, a difference there reported only. pf's references and its
// list of anchors are recorded only. Before the comparison the restore
// waits, in this order, for no thinkpol process (up to 60 s; an agent
// releases its pf reference last, and that can turn pf off), then for the
// guard's record to hold no reference of this boot (up to 30 s), and only
// then, in the run's own boot, turns pf back on if the baseline had it on
// and it is off (`pfctl -e`, checked): the one change a restore makes that
// no journal entry names, since it puts back what the baseline recorded.
// It never turns pf off, never flushes anything, never writes
// /etc/pf.conf, DNS, routes or a Setup: key.
//
// The changes: a file of the run's own in its run directory (the
// self-test's harmless change); a capture, a tcpdump in a process group of
// its own (promiscuous mode off, its filter after `--`, never one that
// looks like an option) whose pid and start time are journaled the moment
// it runs, which the helper reads, writing the pcap record by record and
// watching for the self-test's markers (lab/pcap's reader), and which only
// the restore ends. A helper killed between tcpdump's start and that
// journal line leaves an intent with no pid: a later restore can't show
// that tcpdump is gone, says LEFT, and the reboot that ends it closes the
// run (RESET-BY-REBOOT). And, on macOS, `set skip on <name>` loaded before
// the stock rules, refused unless the rules loaded now are the baseline's,
// they are among what /etc/pf.conf loads (`pfctl -n -v -f`; a pf.conf
// edited and not loaded yet gives a false REBOOT, never a false CLEAN),
// and nothing is skipped already. Its undo does nothing once the name
// isn't skipped (a reboot or another app's load took it); while it is, it
// loads /etc/pf.conf until what that sets matches the baseline, at most
// twice.
//
// Its tests drive real processes, kill -9 and fsync, and in lab nodes
// real root and tcpdump; on a Mac every host tool goes through a fake
// runner and the rest are refused, so no test runs pfctl or tcpdump there.
// What only a Mac shows is on the owner's device checklist.
package safety
