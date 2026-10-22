package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

// Version is the protocol version carried in Init; a worker refuses an Init
// whose version differs, so a half-replaced binary can't mismatch its
// supervisor. Bump it on any wire change here.
const Version = 4

// ErrFull is returned by TrySend when the socket's send buffer is full, so
// the message was not sent; the caller drops it.
var ErrFull = errors.New("ipc: send buffer full")

// Kind is a message's type, its first byte on the wire.
type Kind uint8

const (
	KindInit      Kind = 1
	KindReady     Kind = 2
	KindStop      Kind = 3
	KindConfig    Kind = 4
	KindDatagram  Kind = 5 // data socket: DatagramHeader + datagram, both ways
	KindStream    Kind = 6 // control socket: stream handoff, listener id + consumed bytes, fd attached
	KindListeners Kind = 7 // control socket: JSON []Listener
	KindCounters  Kind = 8 // control socket: JSON SharedCounters, periodically
	KindBlob      Kind = 9 // control socket: one blob seed, a sealed memfd attached
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
	case KindListeners:
		return "listeners"
	case KindCounters:
		return "counters"
	case KindBlob:
		return "blob"
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

const (
	// MaxMessageSize bounds a message, kind byte included: a forwarded
	// datagram with its header fits, and so does any control message.
	MaxMessageSize = 64 << 10
	// MaxFiles bounds the descriptors attached to one message.
	MaxFiles = 4
	// MaxBlobSize bounds a Blob message's memfd.
	MaxBlobSize = 16 << 20
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

// Listener is one of the supervisor's shared listeners, as a worker sees it:
// what it is forwarded arrives tagged with ID.
type Listener struct {
	// ID tags the listener's datagrams and streams. The supervisor never
	// reuses one for another listener.
	ID uint32 `json:"id"`
	// Transport is the transport's name in the map.
	Transport string `json:"transport"`
	// Stream is set for a stream transport: its connections arrive as
	// Stream messages; a datagram transport's datagrams as Datagram
	// messages.
	Stream bool `json:"stream,omitempty"`
	// Address is the public address the supervisor listens on.
	Address string `json:"address"`
}

// ListenersMessage lists every shared listener the worker is forwarded from.
func ListenersMessage(ls []Listener) (Message, error) {
	if ls == nil {
		ls = []Listener{}
	}
	b, err := json.Marshal(ls)
	if err != nil {
		return Message{}, fmt.Errorf("ipc: encode listeners: %w", err)
	}
	return Message{Kind: KindListeners, Payload: b}, nil
}

// DecodeListeners decodes a Listeners message.
func DecodeListeners(m Message) ([]Listener, error) {
	var ls []Listener
	if m.Kind != KindListeners {
		return nil, fmt.Errorf("ipc: expected %v, got %v", KindListeners, m.Kind)
	}
	if err := json.Unmarshal(m.Payload, &ls); err != nil {
		return nil, fmt.Errorf("ipc: decode listeners: %w", err)
	}
	return ls, nil
}

// DatagramHeaderSize is the size of a DatagramHeader on the wire:
//
//	listener id [4, big endian] | family [1: 4 or 6] | address [16] | port [2, big endian]
//
// An IPv4 address sits in the first four address bytes, the rest zero.
const DatagramHeaderSize = 23

// MaxDatagramSize is the largest datagram a Datagram message carries.
const MaxDatagramSize = MaxMessageSize - 1 - DatagramHeaderSize

// DatagramHeader starts every Datagram message: which shared listener, and
// the remote end (where a forwarded datagram came from, or where a reply
// goes).
type DatagramHeader struct {
	Listener uint32
	Remote   netip.AddrPort
}

// Put writes h into b, which holds at least DatagramHeaderSize bytes.
func (h DatagramHeader) Put(b []byte) {
	_ = b[DatagramHeaderSize-1]
	binary.BigEndian.PutUint32(b, h.Listener)
	clear(b[4 : 4+1+16])
	if a := h.Remote.Addr(); a.Is4() {
		b[4] = 4
		a4 := a.As4()
		copy(b[5:], a4[:])
	} else {
		b[4] = 6
		a16 := a.As16()
		copy(b[5:], a16[:])
	}
	binary.BigEndian.PutUint16(b[21:], h.Remote.Port())
}

// ParseDatagram splits a Datagram message's payload into its header and the
// datagram.
func ParseDatagram(payload []byte) (DatagramHeader, []byte, error) {
	if len(payload) < DatagramHeaderSize {
		return DatagramHeader{}, nil, fmt.Errorf("ipc: datagram message of %d bytes", len(payload))
	}
	h := DatagramHeader{Listener: binary.BigEndian.Uint32(payload)}
	var addr netip.Addr
	switch payload[4] {
	case 4:
		addr = netip.AddrFrom4([4]byte(payload[5:9]))
	case 6:
		addr = netip.AddrFrom16([16]byte(payload[5:21]))
	default:
		return DatagramHeader{}, nil, fmt.Errorf("ipc: datagram address family %d", payload[4])
	}
	h.Remote = netip.AddrPortFrom(addr, binary.BigEndian.Uint16(payload[21:]))
	return h, payload[DatagramHeaderSize:], nil
}

// StreamMessage hands a connection to a worker: conn is the connection's
// descriptor (the sender keeps and closes its own copy), consumed the bytes
// the supervisor's router already read from it.
func StreamMessage(listener uint32, conn *os.File, consumed []byte) Message {
	p := make([]byte, 4+len(consumed))
	binary.BigEndian.PutUint32(p, listener)
	copy(p[4:], consumed)
	return Message{Kind: KindStream, Payload: p, Files: []*os.File{conn}}
}

// DecodeStream returns a Stream message's listener id, connection and
// consumed bytes; the caller owns the file.
func DecodeStream(m Message) (listener uint32, conn *os.File, consumed []byte, err error) {
	if m.Kind != KindStream || len(m.Payload) < 4 || len(m.Files) != 1 {
		m.CloseFiles()
		return 0, nil, nil, fmt.Errorf("ipc: malformed %v message", m.Kind)
	}
	return binary.BigEndian.Uint32(m.Payload), m.Files[0], m.Payload[4:], nil
}

// SharedCounters are what the supervisor's shared listeners did for one
// space. The supervisor sends them to that space's worker (a Counters
// message) so the worker can seal them into its own telemetry: they hold
// only the space's own figures, never the node's listeners, addresses or
// other spaces.
type SharedCounters struct {
	// Forwarded counts the datagrams (ForwardedBytes their bytes) the
	// worker's data socket took, Streams the connections handed over.
	Forwarded      uint64 `json:"forwarded"`
	ForwardedBytes uint64 `json:"forwarded_bytes"`
	Streams        uint64 `json:"streams"`
	// Stale and Replayed count the space's authenticated datagrams dropped
	// as too old (clock window, replaced sender) or seen before.
	Stale    uint64 `json:"stale"`
	Replayed uint64 `json:"replayed"`
	// NoWorker counts datagrams dropped while no worker could take them
	// (none running, or its socket gone), WorkerFull those its socket had
	// no room for, OverShare those its fair share refused.
	NoWorker   uint64 `json:"no_worker"`
	WorkerFull uint64 `json:"worker_full"`
	OverShare  uint64 `json:"over_share"`
	// StreamsRefused counts connections of the space that couldn't be
	// handed over (no worker, a full socket, no descriptor).
	StreamsRefused uint64 `json:"streams_refused"`
	// Replies counts datagrams (ReplyBytes their bytes) the worker sent
	// out. Refused: to a remote end none of its links' live datagrams came
	// from lately (NotAllowed), through a listener that is gone
	// (NoListener), past its fair share (OverShare); ReplyErrors failed on
	// the socket.
	Replies           uint64 `json:"replies"`
	ReplyBytes        uint64 `json:"reply_bytes"`
	RepliesNotAllowed uint64 `json:"replies_not_allowed"`
	RepliesNoListener uint64 `json:"replies_no_listener"`
	RepliesOverShare  uint64 `json:"replies_over_share"`
	ReplyErrors       uint64 `json:"reply_errors"`
	// ReplyPeersEvicted counts remote ends a link displaced from its own
	// reply set (a link keeps its latest few).
	ReplyPeersEvicted uint64 `json:"reply_peers_evicted"`
}

// CountersMessage carries a space's shared-listener counters.
func CountersMessage(c SharedCounters) (Message, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return Message{}, fmt.Errorf("ipc: encode counters: %w", err)
	}
	return Message{Kind: KindCounters, Payload: b}, nil
}

// DecodeCounters decodes a Counters message.
func DecodeCounters(m Message) (SharedCounters, error) {
	var c SharedCounters
	if m.Kind != KindCounters {
		return c, fmt.Errorf("ipc: expected %v, got %v", KindCounters, m.Kind)
	}
	if err := json.Unmarshal(m.Payload, &c); err != nil {
		return c, fmt.Errorf("ipc: decode counters: %w", err)
	}
	return c, nil
}
