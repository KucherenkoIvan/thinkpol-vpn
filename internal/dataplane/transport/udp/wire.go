package udp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Wire format, one datagram per packet:
//
//	conn id [8] | session [12] | counter [8] | AES-256-GCM(packet) [n+16]
//
// The connection id is derived from the link secret and the direction, so a
// shared listener finds the link without decrypting anything, and nobody
// without the secret can produce it. The session is chosen by the dialer for
// each Dial: an 8-byte epoch that only grows (nanoseconds, strictly increasing
// within a process) and 4 random bytes. Each session and direction gets its
// own key, so counters can start at zero without ever reusing a nonce. The
// header is the AEAD's associated data.
const (
	connIDSize  = 8
	sessionSize = 12
	counterSize = 8
	headerSize  = connIDSize + sessionSize + counterSize
	tagSize     = 16

	// Overhead is what udp adds to each packet, before IP and UDP headers.
	Overhead = headerSize + tagSize

	maxDatagram = Overhead + transport.MaxPacketSize

	// rejectAfterMessages bounds the counter far below where it could wrap.
	rejectAfterMessages = 1 << 60
	// sessionIdleTimeout is how long a session must stay silent before an
	// older-looking one may replace it (a dialer whose clock went back).
	sessionIdleTimeout = 3 * time.Minute
)

// ConnID is the keyed connection id at the front of every datagram.
type ConnID [connIDSize]byte

type session [sessionSize]byte

func (s session) epoch() uint64 { return binary.BigEndian.Uint64(s[:8]) }

type direction string

const (
	toListener direction = "to listener"
	toDialer   direction = "to dialer"
)

const kdfLabel = "thinkpol udp v1 "

func connIDFor(secret []byte, dir direction) ConnID {
	var id ConnID
	k, err := hkdf.Key(sha256.New, secret, nil, kdfLabel+"conn id "+string(dir), connIDSize)
	if err != nil {
		panic(err) // only for lengths HKDF-SHA256 can't produce
	}
	copy(id[:], k)
	return id
}

func newAEAD(secret []byte, s session, dir direction) cipher.AEAD {
	k, err := hkdf.Key(sha256.New, secret, nil, kdfLabel+"key "+string(dir)+" "+string(s[:]), 32)
	if err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

var lastEpoch atomic.Uint64

func newSession() session {
	var s session
	for {
		last := lastEpoch.Load()
		e := max(uint64(time.Now().UnixNano()), last+1)
		if lastEpoch.CompareAndSwap(last, e) {
			binary.BigEndian.PutUint64(s[:8], e)
			break
		}
	}
	_, _ = rand.Read(s[8:])
	return s
}

type header struct {
	id      ConnID
	sess    session
	counter uint64
}

// parseHeader accepts only datagrams that could hold a packet.
func parseHeader(d []byte) (header, bool) {
	var h header
	if len(d) <= Overhead || len(d) > maxDatagram {
		return h, false
	}
	copy(h.id[:], d[:connIDSize])
	copy(h.sess[:], d[connIDSize:connIDSize+sessionSize])
	h.counter = binary.BigEndian.Uint64(d[connIDSize+sessionSize : headerSize])
	return h, true
}

func nonce(counter uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], counter)
	return n[:]
}

// seal appends the datagram for packet to dst.
func seal(dst []byte, aead cipher.AEAD, h header, packet []byte) []byte {
	dst = append(dst, h.id[:]...)
	dst = append(dst, h.sess[:]...)
	dst = binary.BigEndian.AppendUint64(dst, h.counter)
	return aead.Seal(dst, nonce(h.counter), packet, dst[len(dst)-headerSize:])
}

// open authenticates datagram d and appends its packet to dst. dst must not
// overlap d: on failure Open may scribble over dst's capacity.
func open(dst []byte, aead cipher.AEAD, h header, d []byte) ([]byte, error) {
	return aead.Open(dst, nonce(h.counter), d[headerSize:], d[:headerSize])
}

var datagramPool = sync.Pool{New: func() any { b := make([]byte, 0, maxDatagram); return &b }}
