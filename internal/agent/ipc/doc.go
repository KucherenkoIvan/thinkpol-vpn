// Package ipc is the protocol between a server's supervisor and a space's
// worker (DESIGN.md "Server agent: one worker per space").
//
// Each worker has two AF_UNIX SOCK_SEQPACKET sockets, both halves of pairs
// the supervisor makes, inherited as file descriptors:
//
//   - the control socket (ControlFD = 3): Init, Config, Listeners, Ready,
//     Stop, and the stream handoff. Reliable; a control message is never
//     queued behind bulk data. The supervisor hands a stream over without
//     blocking (Conn.TrySend): a full socket refuses the connection.
//   - the data socket (DataFD = 4): forwarded datagrams both ways. The
//     supervisor sends without blocking (Conn.TrySendDatagram), so a
//     slow or stuck worker drops datagrams instead of blocking the
//     supervisor; the drops are counted. The worker sends its replies
//     blocking, which holds up only itself.
//
// SEQPACKET keeps message boundaries, is reliable and ordered, and carries
// file descriptors (SCM_RIGHTS). The sockets have no name, so nothing else
// can connect. Each socket's send and receive buffers are SocketBuffer
// (2 MiB, about a thousand full-size datagrams, forced past the system's
// maximum where the supervisor may), so a burst rides out a worker's
// scheduling delay instead of being dropped. A message is one packet: a
// Kind byte, then the payload, at most MaxMessageSize bytes in all, with up
// to MaxFiles descriptors.
//
// The control conversation:
//
//	supervisor → worker  Init    (JSON Init) once, first, with the protocol version
//	supervisor → worker  Config  (JSON, or a sealed memfd for a large one) after Init and on change
//	worker → supervisor  Ready   (empty) once sandboxed: the worker serves from now on
//	supervisor → worker  Listeners (JSON []Listener) after Ready and whenever the shared listeners change
//	supervisor → worker  Stream  (listener id + consumed bytes, the connection's fd attached) per routed connection
//	supervisor → worker  Counters (JSON SharedCounters) periodically: the space's own shared-listener figures
//	supervisor → worker  Blob    (a sealed memfd attached) each of the space's blob seeds, once per worker, before the Config that names it
//	supervisor → worker  Stop    (empty) shut down and exit 0
//
// The data socket carries only Datagram messages, both ways: a
// DatagramHeader (the shared listener's id and the remote address: where
// it came from, or where the reply goes), then the datagram, untouched.
//
// EOF on the control socket means the other side is gone. Kinds a side
// doesn't know are errors, not ignored: both ends are always the same
// binary, which the version in Init confirms.
package ipc
