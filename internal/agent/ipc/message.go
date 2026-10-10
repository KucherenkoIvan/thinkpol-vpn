// Package ipc is the protocol between a server's supervisor and a space's
// worker (DESIGN.md "Server agent: one worker per space").
//
// Each worker has one socket: an AF_UNIX SOCK_SEQPACKET pair made by the
// supervisor, whose other end the worker inherits as file descriptor 3
// (WorkerFD). SEQPACKET keeps message boundaries, is reliable and ordered,
// and carries file descriptors (SCM_RIGHTS), so one socket serves control,
// datagram forwarding and stream handoff. Nothing else can connect to it:
// it has no name.
//
// A message is one packet: a Kind byte, then the payload, at most
// MaxMessageSize bytes in all, with up to MaxFiles descriptors attached.
// The conversation:
//
//	supervisor → worker  Init   (JSON Init) first, once the worker's namespace is wired
//	worker → supervisor  Ready  (empty) once sandboxed: the worker serves from now on
//	supervisor → worker  Stop   (empty) shut down and exit 0
//
// The end of the socket (EOF) means the other side is gone: a worker exits,
// the supervisor treats the worker as dead. Kinds a side doesn't know are
// errors, not ignored: both ends are always the same binary. The connection
// handoff (TP-010) adds its kinds here: datagrams forwarded both ways, and
// accepted streams passed as a descriptor plus the bytes already read.
// Payloads too large for a packet (a map envelope) travel as a descriptor
// (a sealed memfd), never through the disk.
package ipc

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

// Kind is a message's type, its first byte on the wire.
type Kind uint8

const (
	KindInit  Kind = 1
	KindReady Kind = 2
	KindStop  Kind = 3
)

func (k Kind) String() string {
	switch k {
	case KindInit:
		return "init"
	case KindReady:
		return "ready"
	case KindStop:
		return "stop"
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

const (
	// MaxMessageSize bounds a message, kind byte included: a forwarded
	// datagram with its header fits, and so does any control message.
	MaxMessageSize = 64 << 10
	// MaxFiles bounds the descriptors attached to one message.
	MaxFiles = 4
	// WorkerFD is the descriptor a worker finds its socket at.
	WorkerFD = 3
)

// Message is one packet on the socket.
type Message struct {
	Kind    Kind
	Payload []byte
	// Files are passed with SCM_RIGHTS. A sender keeps its own copies; a
	// receiver owns what it gets and must close it.
	Files []*os.File
}

// Init is what a worker needs before it starts: who it is, how its
// namespace was wired, and whom to become.
type Init struct {
	// Space is the space's id, hex; the worker checks it against its
	// --space flag.
	Space string `json:"space"`
	// Interface is the namespace's end of the space's veth pair, already
	// up with Addrs and default routes via Gateways.
	Interface string         `json:"interface"`
	Addrs     []netip.Prefix `json:"addrs"`
	Gateways  []netip.Addr   `json:"gateways"`
	// UID and GID are what the worker drops to once sandboxed.
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

// InitMessage encodes init.
func InitMessage(init Init) (Message, error) {
	b, err := json.Marshal(init)
	if err != nil {
		return Message{}, fmt.Errorf("ipc: encode init: %w", err)
	}
	return Message{Kind: KindInit, Payload: b}, nil
}

// DecodeInit decodes an Init message.
func DecodeInit(m Message) (Init, error) {
	var init Init
	if m.Kind != KindInit {
		return init, fmt.Errorf("ipc: expected %v, got %v", KindInit, m.Kind)
	}
	if err := json.Unmarshal(m.Payload, &init); err != nil {
		return init, fmt.Errorf("ipc: decode init: %w", err)
	}
	return init, nil
}

// CloseFiles closes every file attached to m; for a receiver discarding a
// message.
func (m Message) CloseFiles() {
	for _, f := range m.Files {
		_ = f.Close()
	}
}
