package transport

// make lab-test's node phase runs this package's tests on a Linux machine,
// as a user, instead of in a lab node (lab.HostTestsFile): they check
// endpoints, inboxes and shaping without opening a socket.
