// Package ipc is the protocol between a server's supervisor and a space's
// worker (DESIGN.md "Server agent: one worker per space").
//
// Each worker has two AF_UNIX SOCK_SEQPACKET sockets, both halves of pairs
// the supervisor makes, inherited as file descriptors:
//
//   - the control socket (ControlFD = 3): Init, Config, Ready, Stop, and
//     the stream handoff (TP-010). Blocking and reliable; a control message
//     is never queued behind bulk data.
//   - the data socket (DataFD = 4): forwarded datagrams both ways (TP-010).
//     Sent non-blocking (TrySend), so a slow or stuck worker drops datagrams
//     instead of blocking the supervisor; the drops are counted.
//
// SEQPACKET keeps message boundaries, is reliable and ordered, and carries
// file descriptors (SCM_RIGHTS). The sockets have no name, so nothing else
// can connect. A message is one packet: a Kind byte, then the payload, at
// most MaxMessageSize bytes in all, with up to MaxFiles descriptors.
//
// The control conversation:
//
//	supervisor → worker  Init    (JSON Init) once, first, with the protocol version
//	supervisor → worker  Config  (JSON, or a sealed memfd for a large one) after Init and on change
//	worker → supervisor  Ready   (empty) once sandboxed: the worker serves from now on
//	supervisor → worker  Stop    (empty) shut down and exit 0
//
// EOF on the control socket means the other side is gone. Kinds a side
// doesn't know are errors, not ignored: both ends are always the same
// binary, which the version in Init confirms.
package ipc

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

// Version is the protocol version carried in Init; a worker refuses an Init
// whose version differs, so a half-replaced binary can't mismatch its
// supervisor. Bump it on any wire change here.
const Version = 1

// Kind is a message's type, its first byte on the wire.
type Kind uint8

const (
	KindInit     Kind = 1
	KindReady    Kind = 2
	KindStop     Kind = 3
	KindConfig   Kind = 4
	KindDatagram Kind = 5 // data socket, forwarded datagrams (TP-010)
	KindStream   Kind = 6 // control socket, stream handoff: fd + consumed bytes (TP-010)
)

func (k Kind) String() string {
	switch k {
	case KindInit:
		return "init"
	case KindReady:
		return "ready"
	case KindStop:
		return "stop"
	case KindConfig:
		return "config"
	case KindDatagram:
		return "datagram"
	case KindStream:
		return "stream"
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

const (
	// MaxMessageSize bounds a message, kind byte included: a forwarded
	// datagram with its header fits, and so does any control message.
	MaxMessageSize = 64 << 10
	// MaxFiles bounds the descriptors attached to one message.
	MaxFiles = 4
	// ControlFD and DataFD are where a worker finds its two sockets.
	ControlFD = 3
	DataFD    = 4
)

// Message is one packet on a socket.
type Message struct {
	Kind    Kind
	Payload []byte
	// Files are passed with SCM_RIGHTS. A sender keeps its own copies; a
	// receiver owns what it gets and must close it.
	Files []*os.File
}

// Init is what a worker needs before it starts: the protocol version, who it
// is, and how its namespace was wired.
type Init struct {
	// Version is the protocol version (Version); the worker refuses a
	// mismatch.
	Version int `json:"version"`
	// Space is the space's id, hex; the worker checks it against its -space
	// flag.
	Space string `json:"space"`
	// Interface is the namespace's end of the space's veth pair, already
	// up with Addrs and default routes via Gateways.
	Interface string         `json:"interface"`
	Addrs     []netip.Prefix `json:"addrs"`
	Gateways  []netip.Addr   `json:"gateways"`
	// UID and GID are the host ids the worker's user namespace maps its
	// root to; the worker checks the mapping is in place.
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	// PidsMax, when nonzero, caps the worker's processes through its own
	// RLIMIT_NPROC, a fallback where the supervisor's cgroup couldn't.
	PidsMax int64 `json:"pids_max"`
}

// InitMessage encodes init with the current protocol version.
func InitMessage(init Init) (Message, error) {
	init.Version = Version
	b, err := json.Marshal(init)
	if err != nil {
		return Message{}, fmt.Errorf("ipc: encode init: %w", err)
	}
	return Message{Kind: KindInit, Payload: b}, nil
}

// DecodeInit decodes an Init message and checks the protocol version.
func DecodeInit(m Message) (Init, error) {
	var init Init
	if m.Kind != KindInit {
		return init, fmt.Errorf("ipc: expected %v, got %v", KindInit, m.Kind)
	}
	if err := json.Unmarshal(m.Payload, &init); err != nil {
		return init, fmt.Errorf("ipc: decode init: %w", err)
	}
	if init.Version != Version {
		return init, fmt.Errorf("ipc: protocol version %d, want %d", init.Version, Version)
	}
	return init, nil
}

// ConfigMessage carries a space's opaque per-worker configuration (TP-011
// fills it in). A large one travels as a sealed memfd (Files), never a disk
// file; small ones ride in the payload.
func ConfigMessage(config []byte) Message {
	return Message{Kind: KindConfig, Payload: config}
}

// CloseFiles closes every file attached to m; for a receiver discarding a
// message.
func (m Message) CloseFiles() {
	for _, f := range m.Files {
		_ = f.Close()
	}
}
