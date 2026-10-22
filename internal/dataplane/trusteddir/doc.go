//go:build unix

// Package trusteddir opens directories whose contents a process may
// believe: the directory and every directory on its path are owned by the
// process's user (or root), none is a symlink, and none is writable by
// anyone else. The path is walked from / one component at a time with
// openat(O_NOFOLLOW), each checked on its open descriptor, so nothing on
// the way can be swapped for a symlink between the check and the use, and
// no one else can rename a directory on the way while it is used. An
// ancestor writable by others is passed through only when it is sticky
// (like /tmp): there others can add entries but not rename or remove ours,
// and a foreign entry on the path fails the owner check. The directory
// itself is never sticky or writable by others. Whatever is done inside it
// is done relative to its descriptor.
//
// Its users are what decides a node's trust or ownership on disk: the
// agent's state directory and host lock (package agent), netcfg's route
// records and owner locks on macOS, and the leak guard's pf records on
// macOS (package firewall).
//
// # Why every directory on the way
//
// A lock or a record is only as good as its directory. If someone else
// could rename a lock's directory away from under a running holder, the
// next process would lock a fresh file in a new directory at the same
// path, and two holders would run at once; whoever could replace a record
// would choose what its reader deletes or trusts. So every directory from
// / down must be root's (or the process user's) and writable by no one
// else. That rules out macOS's /var/run (root:daemon 0775, not sticky:
// anyone of group daemon could rename what is in it); /private/var/db is
// root's alone all the way up.
//
// The walk follows no symlink, so it refuses /var, /etc and /tmp
// themselves on macOS (symlinks into /private): every macOS default path
// names the real one (the state directory, the agent's lock, netcfg's
// directory; the local API's socket too, whose parent check of its own
// refuses the same).
//
// # Files, locks and records
//
// Files in a trusted directory are opened relative to its descriptor,
// never through a symlink nor blocking on a fifo, and only if regular
// ([ReadFile]); [WriteFile] replaces one atomically (a sibling written,
// synced and renamed over it). [Lock] takes an exclusive flock,
// close-on-exec, so no process this one starts holds it after it.
// [WriteRecord] and [ReadRecord] stamp a file with the boot session it
// was written in ([BootSession], macOS's kern.bootsessionuuid): a
// directory outlives a reboot and what its records name (routes, pf
// references) doesn't, so a record of another boot holds nothing
// ([ErrOtherBoot]).
package trusteddir
