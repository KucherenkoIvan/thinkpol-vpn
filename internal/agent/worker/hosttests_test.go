package worker

// make lab-test's node phase runs this package's tests on a Linux machine,
// as a user, instead of in a lab node (lab.HostTestsFile): they drive the
// shared listeners with a recording sender, and check that a worker started
// without its supervisor's sockets stops before its sandbox.
