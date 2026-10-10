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
// The helpers build without tags so lint and unit tests cover them; the tests
// that need Docker carry the lab build tag and run through make lab-test. See
// lab/README.md.
package lab
