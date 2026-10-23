// Command devicetest is the device-test harness: it runs one ticket's
// device checks on a real Mac, records what they show, and puts the Mac
// back. Only the owner runs it (it needs a terminal's "yes" and the
// owner's sudo); agents build it, test it in the lab, and judge the
// evidence a run leaves. It is a lab tool like labctl and never ships.
//
//	go build -o DIR/ ./lab/devicetest ./lab/devicetest/devicetest-root
//	devicetest plans [TICKET]        the plans, or everything one's run may do
//	devicetest run TICKET            self-test, the plan's steps, restore
//	devicetest selftest              the self-test alone
//	devicetest restore [-forget RUN] restore the run pending a restore
//
// # What a run guarantees
//
// A run prints its plan's listing (everything it may do, in order) and
// asks for yes, then for sudo once: sudo runs a checked copy of
// devicetest-root, built beside devicetest, whose helper starts the run's
// journal, arms the dead-man and takes the baseline before anything
// changes. devicetest-root links the safety core (lab/devicetest/safety,
// frozen) and no plan, so no plan code runs as root. The core holds the
// rest:
//
//   - nothing changes without its undo synced to the journal first, a
//     baseline and an armed dead-man; changes are typed, of the core's
//     kinds, root reads are listings the core allows, and the tool does
//     only what the plan lists: anything else stops the run and asks the
//     owner (continue, or restore and end);
//   - the Mac is put back after a normal end, Ctrl-C, a closed terminal, a
//     crash or kill of either process, and a power loss (at the next
//     `devicetest restore`, which every later run waits for); the result
//     is CLEAN, LEFT with what to do for each item, or REBOOT, and LEFT
//     or REBOOT keeps the run pending until a restore closes it: CLEAN; or
//     in a later boot, with every change of the run's undone or gone with
//     its boot, RESET-BY-REBOOT; or, for what no restore can show, the
//     owner's `devicetest restore -forget RUN` in a later boot, FORGOTTEN.
//     Only CLEAN says the Mac is as it was (safety's doc.go, "Verdicts");
//     a run whose baseline can't read what it compares doesn't start;
//   - before any change, the self-test: one harmless change goes through
//     the journal and back, then the plan's capture must see a marker (one
//     UDP datagram from the interface's address to its IPv4 broadcast
//     address, discard port 9), must not see one its filter excludes (so
//     the check can fail), and must decode through the evidence path
//     (`tcpdump -n -A -r`, stderr kept), within 10 s. Any failure stops
//     the run with nothing of the plan's done;
//   - evidence, never verdicts: ~/thinkpol-evidence/<date>-<ticket>/
//     (-2, -3 for later runs that day), refused inside a git checkout:
//     plan.txt; harness.log (the one terminal's transcript, every line
//     timestamped) and notes.md (what the owner typed); run.json (the
//     listing's and the core's hashes, the tool's commit, the self-test,
//     the restore); selftest/ (selftest.json, the capture's copy and its
//     decode); captures/ (the pcap, tcpdump's stderr, markers.jsonl with
//     the markers and each step's start and end); steps/NN-name/ (each
//     root read's .out, .err and .json with its exit status, and `thinkpol
//     diag` or why there is none); snapshots/ (the baseline and after each
//     restore, raw); actions/ (what each change ran); restore/ and
//     journal/. Captures keep 128 bytes a packet and are never deleted:
//     the evidence is the owner's, kept privately. Root's own state
//     directory keeps the newest 10 runs' journals and snapshots.
//
// "recorded" in the last line means the evidence is complete, never that
// anything passed: an agent judges the folder against the ticket's
// checklist afterwards. Reboot tests print a recovery sheet for the owner
// instead of installing anything that acts at boot.
//
// # How a plan is written
//
// A plan is data in lab/devicetest/plans: a function per ticket returning
// a plan.Plan, listed by plans.All, so nothing in it runs unless asked.
// It is written with lab/devicetest/plan: one capture, and steps, each a
// list of root reads (plan.Read("pfctl", "-s", "Interfaces", "-v")),
// changes (plan.Do with one of the core's kinds, e.g.
// plan.Do(plan.PfSkip("lo"))) and plan.UndoLast, which undoes the plan's
// own newest change. depguard holds plan and plans to a short list of
// standard packages: a plan can't run a command or reach the core, and the
// listing is the whole run. A plan records and never judges: no counting,
// parsing or PASS/FAIL. What a judge decides again and again becomes a Go
// test over a recorded fixture, or a field of `thinkpol diag`. A ticket's
// plan is never bigger than the ticket's own change; a new kind of change
// is a change to the frozen core, in a ticket of its own. Nothing naming a
// server goes into this repository: what will name the exit server comes
// with its driver, from a private file outside every checkout.
package main
