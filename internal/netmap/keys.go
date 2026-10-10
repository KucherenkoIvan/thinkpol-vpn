package netmap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// SpaceID names a space: random, fixed for the life of the space.
type SpaceID [16]byte

// NodeID names a node inside one space: random and opaque, so nodes know
// each other without names. The same server has unrelated ids in the spaces
// it serves.
type NodeID [8]byte

// WireGuardKey is a peer's WireGuard (Curve25519) public key.
type WireGuardKey [32]byte

// NodePublicKey is the X25519 key a node's map section is sealed to. A node
// has one per space it serves, separate from its WireGuard key, generated on
// the node and never copied off it.
type NodePublicKey [32]byte

// NodePrivateKey opens a node's map section.
type NodePrivateKey [32]byte

// NewSpaceID returns a random space id.
func NewSpaceID() SpaceID {
	var id SpaceID
	_, _ = rand.Read(id[:]) // crypto/rand.Read never fails
	return id
}

// NewNodeID returns a random node id.
func NewNodeID() NodeID {
	var id NodeID
	_, _ = rand.Read(id[:])
	return id
}

// GenerateNodeKey returns a new random node key.
func GenerateNodeKey() NodePrivateKey {
	var k NodePrivateKey
	_, _ = rand.Read(k[:])
	return k
}

// Public returns the public half of k.
func (k NodePrivateKey) Public() NodePublicKey {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// X25519 with the base point never yields the all-zero output.
		panic(fmt.Sprintf("netmap: deriving a node public key: %v", err))
	}
	return NodePublicKey(pub)
}

// String keeps the key out of logs and error messages.
func (NodePrivateKey) String() string { return "NodePrivateKey(redacted)" }

// GoString keeps the key out of %#v.
func (k NodePrivateKey) GoString() string { return k.String() }

func (id SpaceID) String() string { return hex.EncodeToString(id[:]) }
func (id SpaceID) IsZero() bool   { return id == SpaceID{} }

func (id NodeID) String() string { return hex.EncodeToString(id[:]) }
func (id NodeID) IsZero() bool   { return id == NodeID{} }

func (k WireGuardKey) String() string { return hex.EncodeToString(k[:]) }
func (k WireGuardKey) IsZero() bool   { return k == WireGuardKey{} }

func (k NodePublicKey) String() string { return hex.EncodeToString(k[:]) }
func (k NodePublicKey) IsZero() bool   { return k == NodePublicKey{} }

// ParseSpaceID parses a hex space id.
func ParseSpaceID(s string) (SpaceID, error) { return parseHex[SpaceID]("space id", s) }

// ParseNodeID parses a hex node id.
func ParseNodeID(s string) (NodeID, error) { return parseHex[NodeID]("node id", s) }

// ParseNodePublicKey parses a hex node public key and rejects keys no
// honest node has (see [NodePublicKey.Check]).
func ParseNodePublicKey(s string) (NodePublicKey, error) {
	k, err := parseHex[NodePublicKey]("node public key", s)
	if err != nil {
		return k, err
	}
	return k, k.Check()
}

// probeScalar is any fixed non-zero scalar: X25519 with it fails exactly
// for the low-order points, whose product with every clamped scalar is zero.
var probeScalar = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// Check rejects public keys an honest node never has: non-canonical
// encodings (top bit set, or a value of at least 2^255 - 19) and low-order
// points, which would let a section be sealed to a key whose shared
// secret is predictable.
func (k NodePublicKey) Check() error {
	if k[31]&0x80 != 0 {
		return fmt.Errorf("netmap: node public key %v: top bit set", k)
	}
	// p = 2^255 - 19, little-endian: ed ff … ff 7f.
	if k[31] == 0x7f && k[0] >= 0xed && allFF(k[1:31]) {
		return fmt.Errorf("netmap: node public key %v: not reduced modulo 2^255-19", k)
	}
	if _, err := curve25519.X25519(probeScalar[:], k[:]); err != nil {
		return fmt.Errorf("netmap: node public key %v: low-order point", k)
	}
	return nil
}

func allFF(b []byte) bool {
	for _, c := range b {
		if c != 0xff {
			return false
		}
	}
	return true
}

// ParseWireGuardKey parses a hex WireGuard public key.
func ParseWireGuardKey(s string) (WireGuardKey, error) {
	return parseHex[WireGuardKey]("WireGuard key", s)
}

func parseHex[T ~[8]byte | ~[16]byte | ~[32]byte](what, s string) (T, error) {
	var v T
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(v) {
		return v, fmt.Errorf("netmap: %s must be %d hex bytes", what, len(v))
	}
	return T(b), nil
}

// ParseNodePrivateKey parses a hex node private key.
func ParseNodePrivateKey(s string) (NodePrivateKey, error) {
	return parseHex[NodePrivateKey]("node private key", s)
}
