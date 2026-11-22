package ipc

// make lab-test's node phase runs this package's tests on a Linux machine,
// as a user, instead of in a lab node (lab.HostTestsFile): they pass
// messages and descriptors over socket pairs the test makes itself.
