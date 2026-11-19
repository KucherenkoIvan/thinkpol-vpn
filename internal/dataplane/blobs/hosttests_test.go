package blobs

// make lab-test's node phase runs this package's tests on a Linux machine,
// as a user, instead of in a lab node (lab.HostTestsFile): blobs travel
// between services over a loopback test network, with no interface binding.
