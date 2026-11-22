package main

import "github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"

// physicalInterface is the interface of the IPv4 default route, asked of
// the kernel (netcfg's lookup, as `route -n get default`).
func physicalInterface() (string, error) {
	name, _, err := netcfg.DefaultInterface(netcfg.IPv4)
	return name, err
}

// restoreWaitNote is said before the restore, and in the listing: what a
// restore waits for on a Mac (safety's settle), and which of its notes
// the thinkpol service, installed on purpose, makes expected.
const restoreWaitNote = "the restore waits up to 60 s for no thinkpol process to run, then up to 30 s for thinkpol's leak guard " +
	"to release its pf reference. With the thinkpol service installed, its agent always runs: expect the full 60 s and the note " +
	`"a thinkpol process still runs after 60 s (pids [...]): stop it, then run devicetest restore", which asks nothing of you ` +
	"(the verdict comes from the comparison, not that note). Disconnected, the guard holds no reference and that wait ends at once; " +
	`connected, expect 30 s more and "the guard still holds a pf reference after 30 s: ...": run thinkpol disconnect, then devicetest restore`
