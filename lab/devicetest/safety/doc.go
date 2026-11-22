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
// reaches the core without moving the pin, and its review says so; what
// the core's verdicts depend on in firewall's readers (which pfctl
// answers mean a missing anchor, which lines are ALTQ chatter, a cut
// listing, each for the anchors, the skips and pf's status) is pinned by
// the core's own tests too
// (TestTheMacSurfacesReadPfctlAndScutil), so such a change fails here.
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
//     back (for pf, what loading pf.conf sets that the precondition
//     doesn't check, limits, timeouts and the debug level, comes out LEFT
//     when another app had set it, never CLEAN), and an undo that checks
//     first whether the change is there, so it is safe to repeat. Root
//     reads are listings of the shapes the core allows; nothing else runs
//     as root.
//   - A normal end, or Ctrl-C (any number of them), undoes every change,
//     newest first, then compares the host, in a fresh snapshot, with its
//     baseline (Result). Every root mode ignores the terminal's signals
//     from its first line; the user side asks the helper to restore.
//   - A closed terminal, or the user side killed: the helper's input ends
//     and it restores at once.
//   - The helper crashed, killed or hung: the dead-man, a process in a
//     session of its own, restores its own run from the journal when the
//     helper is gone (watched by pid and start time; an unreaped zombie is
//     gone), past the plan's budget when no restore is making progress
//     (the heartbeat changes only when a restore makes progress, a
//     snapshot after each surface it reads, never on a timer), or at its
//     limit, budget + 10 min, whatever the heartbeat says. It kills the
//     helper's pid alone: a pfctl the helper started runs on to its end,
//     in a process group of its own (every command the core runs is). Only
//     three of those change pf: the load of the run's skip, whose outcome
//     isn't journaled yet, which the undo then never takes for gone (LEFT,
//     closed by a reboot); a load of /etc/pf.conf, the undo's own, the
//     same load the dead-man's undo makes while the skip is still there;
//     or the restore's `pfctl -e`, which turns pf on only when the
//     baseline had it on, what the dead-man's own restore puts back too.
//     So no orphan turns into a false CLEAN. Its budget
//     counts the larger of the monotonic and wall-clock time since it
//     started: setting the clock back can't hold it, and a Mac asleep,
//     whose monotonic clock stops, counts as time passed. A stop file
//     disarms it; only a file actually there counts, never an error
//     reading the directory.
//   - Everything killed, or the power lost: the journal and the active
//     pointer stay in root's state directory, and every later run is
//     refused until `devicetest restore` replays the journal. A volatile
//     change (kernel state: a capture, pf's rules) of an earlier boot is
//     checked gone with that boot, never assumed, and nothing is changed
//     in a boot the run never touched; a persistent one is undone. The
//     journal and the state directory are synced with F_FULLFSYNC on
//     macOS, past the drive's cache.
//   - A result that doesn't close the run leaves it pending (a "left"
//     pointer, on disk before the active one goes): no run starts until a
//     restore closes it.
//
// # Verdicts
//
// CLEAN: every change undone and the host equal to the baseline. LEFT:
// something differs or failed to undo, each item with what to do next.
// REBOOT: after the pf-skip undo's loads of /etc/pf.conf, pf still lists
// the skip this run's load left: the core's own pf change survived its
// undo, and a reboot clears it; any other difference, whoever made it,
// another app's skips and skips that can't be read included, is LEFT; DNS
// and the dummynet rules are reported only. LEFT and REBOOT keep the run
// pending. NOTHING-TO-RESTORE: no run was pending, or the run didn't start
// (its result says why), or it was killed before it took a baseline or
// made a change; nothing was compared. RESET-BY-REBOOT: a pending run
// restored in a later boot, with no change of its own left in its journal
// (each undone, or checked gone with the boot it was made in) and the host
// not shown equal to the baseline: what differs is the new boot's.
// FORGOTTEN: `devicetest restore -forget RUN`, the owner naming a pending
// run in a later boot than its own: the restore's undos run first when its
// journal reads back, so only what no undo could close is forgotten (a
// change of its own that can't be undone), and a journal that doesn't read
// back is closed as it is; the result shows what the undos did, what the
// journal still says and how the host compares now, and proves nothing.
// CLEAN and the last three close the run; only CLEAN says the host is as
// it was.
//
// One run is beyond both: one whose record (run.json) or directory can't
// be opened, which no restore can replay and nothing can tell the boot of
// (a missing journal is no obstacle: -forget makes one to close). That is
// disk corruption, and root removes `active` and `left` from the state
// directory by hand: the only step the harness leaves to a hand.
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
// pool limits, global timeouts and debug level (a ruleset load resets
// those too), Apple's AirDrop and Application Firewall anchors and
// thinkpol's guard anchor, and pf's state; `scutil --dns` without its
// reach lines, and the dummynet rules (whether pfctl lists them is for a
// device run to show), are compared too, a difference there reported only
// (and the same unreadable answer at both ends is no difference). pf's
// references and its list of anchors are recorded only. Before the
// comparison the restore waits, in this order, for no thinkpol process
// (up to 60 s; an agent releases its pf reference last, and that can turn
// pf off), then for the guard's record to hold no reference of this boot
// (up to 30 s), and only then, in the run's own boot, turns pf back on if
// the baseline had it on and it is off (`pfctl -e`, checked): the one
// change a restore makes that no journal entry names, since it puts back
// what the baseline recorded. It never turns pf off, never flushes
// anything, never writes /etc/pf.conf, DNS, routes or a Setup: key.
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
// they are among what /etc/pf.conf loads (`pfctl -n -v -f`, over a
// baseline listing of at least one rule; a pf.conf edited and not loaded
// yet leaves rules the baseline didn't have, LEFT, never a false CLEAN),
// and nothing is skipped already; what its load left in pf's main rules,
// nat rules and skipped interfaces is journaled. The kernel takes a name
// ending in a letter as a prefix of names with a number after it (`lo`
// skips lo0), so its undo goes by the skipped interfaces against the
// baseline, never by the name. In the run's boot: a load whose outcome
// was never journaled (the helper died, or reading pf after it failed)
// fails LEFT, nothing loaded, since nothing tells the run's ruleset from
// another app's (the LEFT names why, when the load itself failed); a skip
// pf listed after the load and no longer lists leaves nothing to do
// (another app's load took it: in the run's boot, no reboot came
// between). Otherwise it loads /etc/pf.conf once, and a second time only
// when the skip alone still differs from the baseline, is still the run's
// and no other skip is listed beside it, deciding on the read after the
// last load (REBOOT while pf lists the run's skip; LEFT for skips another
// app loaded after the undo's load, or that can't be read; each saying
// whether each load failed), but only while pf's main rules, nat rules
// and skipped interfaces are all still what the run's load left: another
// app's ruleset loaded since (a kill switch, with skips of its own) is
// never wiped, and the undo fails LEFT instead. A skip pf never listed,
// even right after the load (a Mac whose `pfctl -s Interfaces -v` marks
// nothing), can't be shown gone: it loads /etc/pf.conf once and fails
// LEFT, and the reboot that clears it closes the run. In a later boot it
// loads nothing and fails unless the skipped interfaces are the
// baseline's. A read of pf before any load that fails names each surface
// and loads nothing. What it can't tell from its own load (pf keeps no
// owner for a ruleset or a skip): another app's that left exactly the
// same rules, nat and skips, or one landing between the undo's check and
// its reload, is replaced by /etc/pf.conf's, and the comparison can say
// CLEAN without it; another app's skip on the run's interface, with rules
// or nat of its own, loaded after the undo's load, reads as the run's
// skip surviving, REBOOT, and if the restore after the reboot still lists
// it, that app loads it (the REBOOT says so): `devicetest restore
// -forget` closes the run.
//
// On a Mac whose pfctl marks no skipped interface (the one in the first
// device run), every skip check sees nothing: the precondition's
// "nothing skipped", the undo's comparison with the skips its load left,
// and "the skip is gone". A ruleset another app loaded before the run
// that is the stock rules plus a skip of its own passes the precondition,
// so the run's own load goes over it; one loaded after the run's looks
// like the run's, so the undo loads /etc/pf.conf once over it. The
// comparison shows neither loss; on such a Mac every pf-skip run ends
// LEFT, never CLEAN, and a later boot closes it RESET-BY-REBOOT (its
// skips always look like the baseline's).
//
// Its tests drive real processes, kill -9 and fsync, and in lab nodes
// real root and tcpdump; on a Mac every host tool goes through a fake
// runner and the rest are refused, so no test runs pfctl or tcpdump there.
// What only a Mac shows is on the owner's device checklist.
package safety
