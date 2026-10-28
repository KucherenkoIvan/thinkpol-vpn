// Package lab runs thinkpol nodes in Docker containers on separate networks
// and lets Go tests drive them: exec in a node, wait for a condition, capture
// packets where the censor sits.
//
// Each test declares the topology it needs (Standard is the usual one) and
// gets a lab of its own: a Compose project named after the checkout and the
// test, labelled as the lab's, on subnets allocated for it, sealed off from
// everything outside the lab. Nothing is shared between tests or between
// checkouts, so several can run at once, and tear-down never touches what
// isn't the lab's.
//
// The binaries are per process, not per lab: each process that starts labs
// (a lab test binary, labctl gotest) builds thinkpol, the lab's tools and
// the test binaries GoTest runs once, into lab/bin/run-*, a directory of
// its own that its labs mount at BinDir, so two runs from one checkout never
// rebuild a binary the other's containers run. The process holds a lock file
// inside the directory and removes the directory when it ends (Main,
// RemoveRunBinaries); creating, sweeping and removing run directories are
// serialized by a lock in the checkout's lab/.run. A directory whose lock
// nobody holds was left by a run that died (interrupted, killed, a -timeout
// panic): the next run, or labctl down, removes it. A failed test's lab kept
// with KeepEnv marks its directory kept, and only labctl down removes that,
// with the lab. UpDetached's lab (make lab-up) outlives labctl, so its
// binaries are its own, in lab/.run/<project>/bin, and go with it.
//
// The helpers build without tags so lint and unit tests cover them; the tests
// that need Docker carry the lab build tag and run through make lab-test. See
// lab/README.md.
package lab
