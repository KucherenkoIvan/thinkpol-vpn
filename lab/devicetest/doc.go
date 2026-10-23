// Command devicetest is the device-test harness: it runs one ticket's
// device checks on a real Mac, records what they show, and puts the Mac
// back. Only the owner runs it (it needs a terminal's "yes" and the
// owner's sudo); agents build it, test it in the lab, and judge the
// evidence a run leaves. It is a lab tool like labctl and never ships.
//
//	devicetest plans [TICKET]        the plans, or everything one may do
//	devicetest run TICKET            self-test, the plan's steps, restore
//	devicetest selftest              the self-test alone
//	devicetest restore               finish an unfinished run from its journal
//
// # What a run guarantees
//
// A run prints its plan's listing (everything it may do, in order), asks
// for yes, then sudo once: the helper, the only root process, starts the
// run's journal, arms the dead-man and takes the baseline before anything
// changes. The safety core (lab/devicetest/safety, frozen) holds the
// rest:
//
//   - nothing changes without its undo synced to the journal first, a
//     baseline and an armed dead-man; changes are typed actions of the
//     core's, root reads are listings the core allows, and the tool does
//     only what the plan lists: anything else stops the run and asks the
//     owner (continue, or restore and end);
//   - the Mac is put back after a normal end, Ctrl-C, a closed terminal, a
//     crash or kill of either process, and a power loss (at the next
//     `devicetest restore`, which every later run waits for); the result
//     is CLEAN, LEFT with what to do for each item, or REBOOT;
//   - before any change, the self-test: one harmless change goes through
//     the journal and back, then each capture must see a marker (one UDP
//     datagram from the interface's address to its IPv4 broadcast
//     address, discard port 9), must not see one its filter excludes (so
//     the check can fail), and must decode through the evidence path
//     (`tcpdump -n -A -r`, stderr kept), all within 10 s. Any failure
//     stops the run with nothing of the plan's done;
//   - evidence, never verdicts: ~/thinkpol-evidence/<date>-<ticket>/
//     (-2, -3 for later runs that day), refused inside a git checkout:
//     plan.txt; harness.log (the one terminal's transcript, every line
//     timestamped) and notes.md (what the owner typed); run.json (the plan's
//     and the core's hashes, the tool's commit, the self-test, the restore);
//     selftest/ (selftest.json, the capture's copy and its decode);
//     captures/ (each capture's pcap and tcpdump's stderr, markers.jsonl
//     with the markers and each step's start and end); steps/NN-name/ (each
//     root read's .out, .err and .json with its exit status, and `thinkpol
//     diag` or why there is none); snapshots/ (the baseline and after the
//     restore, raw); actions/ (what each change ran); restore/ and
//     journal/. Captures keep 128 bytes a packet and are never deleted by
//     the tool: they stay the owner's, privately.
//
// "recorded" in the last line means the evidence is complete, never that
// anything passed: an agent judges the folder against the ticket's
// checklist afterwards. Reboot tests aren't in it yet; when they come,
// the tool prints a recovery sheet for the owner instead of installing
// anything that acts at boot.
//
// # How a plan is written
//
// A plan is data in lab/devicetest/plans, one file per ticket, written
// with lab/devicetest/plan: steps, each a list of root reads
// (plan.Root("pfctl", "-s", "Interfaces", "-v")), changes (plan.Make with
// an action of the core's, e.g. plan.PfMain("set skip on lo")) and
// plan.UndoLast. Plans can't import the core or os/exec (depguard): every
// command goes through the recorder, and the listing is the whole run. A
// plan records and never judges: no counting, parsing or PASS/FAIL. What
// a judge decides again and again becomes a Go test over a recorded
// fixture, or a field of `thinkpol diag`. A ticket's plan is never bigger
// than the ticket's own change; a new kind of change is a change to the
// frozen core, in a ticket of its own.
//
// A plan that needs the exit server says so (NeedsExit); only then is the
// private config file read (-config, $THINKPOL_DEVICETEST_CONFIG, or
// ~/.config/thinkpol-devicetest/config.yaml): it must be the owner's, mode
// 0600, outside every git checkout. Nothing naming a server goes into this
// repository. The exit driver itself isn't built yet.
package main
