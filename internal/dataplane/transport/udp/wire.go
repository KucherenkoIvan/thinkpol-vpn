package udp

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Wire format, one datagram per packet:
//
//	conn id [8] | nonce [24] | XChaCha20-Poly1305(sender [8] | counter [8] | packet) [16+n+16]
//
// The connection id is derived from the link secret and the direction, so a
// shared listener finds the link without decrypting anything, and nobody
// without the secret can produce it; it is the AEAD's associated data. Each
// direction of a credential has one key (HKDF-SHA256 from the secret) and
// every datagram a fresh random 192-bit nonce, so no state is needed to keep
// nonces unique: not across restarts, redials or table changes.
//
// Inside, a random sender id per link end and a counter feed the receiver's
// replay filter. That filter is a cheap pre-filter, reset by restarts;
// WireGuard's own replay protection is the guarantee.
const (
	connIDSize  = 8
	nonceSize   = chacha20poly1305.NonceSizeX
	senderSize  = 8
	counterSize = 8
	tagSize     = chacha20poly1305.Overhead

	clearSize = connIDSize + nonceSize
	innerSize = senderSize + counterSize

	// Overhead is what udp adds to each packet, before IP and UDP headers.
	Overhead = clearSize + innerSize + tagSize

	maxDatagram = Overhead + transport.MaxPacketSize

	// rejectAfterMessages bounds counters far below where they could wrap.
	rejectAfterMessages = 1 << 60
)

// ConnID is the keyed connection id at the front of every datagram.
type ConnID [connIDSize]byte

type senderID [senderSize]byte

type direction string

const (
	toListener direction = "to listener"
	toDialer   direction = "to dialer"
)

const kdfLabel = "thinkpol udp v1 "

func derive(secret []byte, label string, n int) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, kdfLabel+label, n)
	if err != nil {
		panic(err) // only for lengths HKDF-SHA256 can't produce
	}
	return k
}

func connIDFor(secret []byte, dir direction) ConnID {
	var id ConnID
	copy(id[:], derive(secret, "conn id "+string(dir), connIDSize))
	return id
}

func newAEAD(secret []byte, dir direction) cipher.AEAD {
	aead, err := chacha20poly1305.NewX(derive(secret, "key "+string(dir), chacha20poly1305.KeySize))
	if err != nil {
		panic(err)
	}
	return aead
}

func newSenderID() senderID {
	var s senderID
	_, _ = rand.Read(s[:])
	return s
}

// connIDOf accepts only datagrams that could hold a packet.
func connIDOf(d []byte) (ConnID, bool) {
	var id ConnID
	if len(d) <= Overhead || len(d) > maxDatagram {
		return id, false
	}
	copy(id[:], d)
	return id, true
}

var plainPool = sync.Pool{New: func() any { b := make([]byte, 0, innerSize+transport.MaxPacketSize); return &b }}

// seal appends the datagram carrying packet to dst.
func seal(dst []byte, aead cipher.AEAD, id ConnID, sender senderID, counter uint64, packet []byte) []byte {
	dst = append(dst, id[:]...)
	start := len(dst)
	dst = append(dst, make([]byte, nonceSize)...)
	_, _ = rand.Read(dst[start:])
	pp := plainPool.Get().(*[]byte)
	defer plainPool.Put(pp)
	plain := append((*pp)[:0], sender[:]...)
	plain = binary.BigEndian.AppendUint64(plain, counter)
	plain = append(plain, packet...)
	*pp = plain
	return aead.Seal(dst, dst[start:], plain, dst[:connIDSize])
}

var errShortPlaintext = errors.New("udp: datagram too short")

// open authenticates datagram d and appends its plaintext to dst, returning
// the sender, counter and packet. dst must not overlap d unless it is exactly
// d's ciphertext: on failure Open may scribble over dst's capacity.
func open(dst []byte, aead cipher.AEAD, d []byte) (senderID, uint64, []byte, error) {
	var s senderID
	plain, err := aead.Open(dst, d[connIDSize:clearSize], d[clearSize:], d[:connIDSize])
	if err != nil {
		return s, 0, nil, err
	}
	if len(plain) <= innerSize {
		return s, 0, nil, errShortPlaintext
	}
	copy(s[:], plain)
	return s, binary.BigEndian.Uint64(plain[senderSize:innerSize]), plain[innerSize:], nil
}

var datagramPool = sync.Pool{New: func() any { b := make([]byte, 0, maxDatagram); return &b }}
