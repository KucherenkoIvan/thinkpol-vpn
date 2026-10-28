// Package lab runs thinkpol nodes in Docker containers on separate networks
// and lets Go tests drive them: exec in a node, wait for a condition, capture
// packets where the censor sits.
//
// Each test declares the topology it needs (Standard is the usual one) and
// gets a lab of its own: a Compose project named after the checkout and the
// test, labelled as the lab's, on subnets allocated for it, sealed off from
// everything outside the lab. No lab state is shared between tests or
// between checkouts, so several can run at once, and tear-down never
// touches what isn't the lab's.
//
// The binaries are per run, not per lab: each process that starts labs (a
// lab test binary, labctl gotest) builds thinkpol, the lab's tools and,
// once per package, the test binaries GoTest runs into lab/bin/run-*, a
// directory of its own that its labs mount at BinDir, so two runs from one
// checkout never rebuild a binary the other's containers run. The run holds
// a lock file inside the directory and removes the directory when it ends
// (Main, RemoveRunBinaries); creating, sweeping and removing run
// directories are serialized by a lock in the checkout's lab/.run. A
// directory whose lock nobody holds was left by a run that died
// (interrupted, killed, a -timeout panic): the next run, or labctl down,
// removes it. With KeepEnv set, a run lists in the directory's .kept every
// lab it starts, before the lab starts; such a directory, left by a run
// that kept a failed test's lab or died, is removed only by labctl down,
// and only once none of the labs it lists is up. UpDetached's lab (make
// lab-up) outlives labctl, so its binaries are its own, in
// lab/.run/<project>/bin, and go with it.
//
// The helpers build without tags so lint and unit tests cover them; the tests
// that need Docker carry the lab build tag and run through make lab-test. See
// lab/README.md.
package lab
