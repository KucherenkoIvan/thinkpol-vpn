// Package lab runs thinkpol nodes in Docker containers on separate networks
// and lets Go tests drive them: exec in a node, wait for a condition, capture
// packets where the censor sits.
//
// Each test declares the topology it needs (Standard is the usual one) and
// gets a lab of its own (Start): a Compose project named after the
// checkout, the run and the test, labelled as the lab's, on subnets
// allocated for it, sealed off from everything outside the lab. No lab is
// shared between runs or checkouts, so several can run at once, and
// tear-down never touches what isn't the lab's. Within a process, tests of
// one topology can share labs one after another instead (Pool): a test
// takes a started lab, and when it ends the lab is reset to the state it
// came up in and checked (Snapshot, Lab.Reset) before the next test gets
// it; a lab whose check fails, or whose test failed, is torn down (or
// kept, with KeepEnv). The check reads only what nodeStateScript lists: a
// test that changes anything else needs a lab of its own (Start).
//
// A run is the processes that share a run id (RunEnv): make lab-test gives
// its lab tests and its labctl gotest one, and every other process that
// starts labs makes up its own. Test and gotest labs carry it in their
// names, with a 24-bit hash that covers the process too (processID), so
// two runs from one checkout, or two processes of one run, practically
// never replace each other's labs, and make lab-test's clean-up (DownRun)
// removes its own run's labs only. A process that is killed and retried
// under the same run id leaves its labs up beside the retry's, under other
// names, until labctl down -run removes the run: make lab-test does that at
// its end unless THINKPOL_LAB_KEEP is set or make itself is killed. labctl
// down (DownCheckout) still removes every lab of the checkout.
//
// The binaries are per run, not per lab: each process that starts labs (a
// lab test binary, labctl gotest) builds them into lab/bin/run-*, a
// directory of its own that its labs mount at BinDir: thinkpol and the
// lab's tools once, and each package's tests the first time GoTest runs
// them. So two runs from one checkout never rebuild a binary the other's
// containers run. The run holds a lock file inside the directory and
// removes the directory when it ends (Main, RemoveRunBinaries); creating,
// sweeping and removing run directories are serialized by a lock in the
// checkout's lab/.run. A directory whose lock nobody holds was left by a
// run that died (interrupted, killed, a -timeout panic): the next run, or
// labctl down, removes it. With KeepEnv set, a run lists in the
// directory's .kept every lab it starts, before the lab starts; such a
// directory, left by a run that kept a failed test's lab or died, is
// removed only by labctl down, and only once none of the labs it lists is
// up. UpDetached's lab (make lab-up) outlives labctl, so its binaries are
// its own, in lab/.run/<project>/bin, and go with it.
//
// GoTestEach, given a GoTestCache, builds each package's test binary before
// starting its lab and skips the lab when a pass recorded under the same key
// still holds (lab/testcache: the binary, built with -trimpath so that the
// same sources build the same binary from any checkout, the image, the
// engine, the harness, the args and env, and the files the binary read
// through package os, which it lists in its -test.testlogfile, read back
// from the node before the lab goes down). Only passes are recorded, for a
// week, and not when a checkout input changed during the run (so a test
// that walks the checkout stays out of lab/bin, which the run's other
// phases write meanwhile). Each package
// run in a lab reports its time split into its queue for one of the run's
// labs, slot wait, lab start, tests and teardown (LabPhases).
//
// GoTestEach's packages share their labs through a pool of its own
// (nodePool, a Pool that Main doesn't know of, closed when GoTestEach
// returns) of as many labs as packages run at once: a package takes an
// idle lab or starts one, and its lab is reset and checked before the next
// package gets it. A failed package's lab is torn down, never kept, as a
// fresh one is; so is one whose check failed, and one given back while as
// many labs are idle as packages may still take one (Pool.countTakers): its
// slot is what the lab/ tests wait for near the end of the phase. A failed
// tear-down of a pooled lab fails the phase, as a fresh lab's does. A package with FreshLabFile
// changes what the check doesn't read, and gets a lab of its own. The
// cache's key names no lab, so a package run in a pooled lab records and
// finds the same passes as one run in a fresh lab; the test log it reads
// back is the package's own, as the reset removed the last package's.
//
// A package marked with HostTestsFile needs no node: on a Linux machine,
// run as a user (never as root), labctl gotest runs it there with
// GoTestOnHost, plain go test without THINKPOL_LAB and without cgo, built
// with -trimpath so that go test's own cache serves it from another
// checkout of the same sources, and fails it if any of its tests skips.
//
// The helpers build without tags so lint and unit tests cover them; the tests
// that need Docker carry the lab build tag and run on the host through make
// lab-test, or make lab-gotest for the packages it is given (labctl gotest
// -tagged, GoTestLabTagged). See lab/README.md.
package lab
