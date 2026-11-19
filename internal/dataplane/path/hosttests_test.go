package path

// make lab-test's node phase runs this package's tests on a Linux machine,
// as a user, instead of in a lab node (lab.HostTestsFile): paths run over
// in-memory transports and a channel TUN, and a test keeps the package off
// sockets.
