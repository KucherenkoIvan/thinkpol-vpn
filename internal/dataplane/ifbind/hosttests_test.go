package ifbind

// make lab-test's node phase runs this package's tests on a Linux machine,
// as a user, instead of in a lab node (lab.HostTestsFile): on Linux only the
// network name's family is tested; nothing binds a socket.
