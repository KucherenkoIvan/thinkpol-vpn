// Package lab runs thinkpol nodes in Docker containers on separate networks
// and lets Go tests drive them: exec in a node, wait for a condition, capture
// packets where the censor sits.
//
// Each test declares the topology it needs (Standard is the usual one) and
// gets a lab of its own: a Compose project named after the checkout, the
// run and the test, labelled as the lab's, on subnets allocated for it,
// sealed off from everything outside the lab. No lab state is shared
// between tests, runs or checkouts, so several can run at once, and
// tear-down never touches what isn't the lab's.
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
// still holds (lab/testcache: the binary, the image, the engine, the
// harness, the args and env, and the files the binary read through package
// os, which it lists in its -test.testlogfile, read back from the node
// before the lab goes down). Only passes are recorded, for a week, and not
// when a checkout input changed during the run. Each package run in a lab
// reports its time split into slot wait, lab start, tests and teardown
// (LabPhases).
//
// A package marked with HostTestsFile needs no node: on a Linux machine
// labctl gotest runs it there with GoTestOnHost, plain go test without
// THINKPOL_LAB, and fails it if any of its tests skips.
//
// The helpers build without tags so lint and unit tests cover them; the tests
// that need Docker carry the lab build tag and run on the host through make
// lab-test, or make lab-gotest for the packages it is given (labctl gotest
// -tagged, GoTestLabTagged). See lab/README.md.
package lab
