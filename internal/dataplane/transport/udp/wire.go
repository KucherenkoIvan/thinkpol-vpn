package udp

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Wire format, one datagram per packet:
//
//	conn id [8] | nonce [24] | XChaCha20-Poly1305(sender [12] | sent [4] | counter [8] | packet) [24+n+16]
//
// See the package documentation for what each part is for.
const (
	connIDSize  = 8
	nonceSize   = chacha20poly1305.NonceSizeX
	senderSize  = 12 // creation time in Unix nanoseconds [8] | random [4]
	sentSize    = 4  // Unix seconds, uint32
	counterSize = 8
	tagSize     = chacha20poly1305.Overhead

	clearSize = connIDSize + nonceSize
	innerSize = senderSize + sentSize + counterSize

	// Overhead is what udp adds to each packet, before IP and UDP headers.
	Overhead = clearSize + innerSize + tagSize

	maxDatagram = Overhead + transport.MaxPacketSize

	// maxClockSkew is how far a datagram's sealed send time may be from the
	// receiver's clock.
	maxClockSkew = 5 * time.Minute
	// connIDPeriod is how often connection ids change.
	connIDPeriod = time.Hour
)

type connID [connIDSize]byte

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

func epochOf(t time.Time) int64 { return t.Unix() / int64(connIDPeriod/time.Second) }

func connIDFor(secret []byte, dir direction, epoch int64) connID {
	var id connID
	copy(id[:], derive(secret, "conn id "+string(dir)+" "+strconv.FormatInt(epoch, 10), connIDSize))
	return id
}

// rotatingID is a sender's connection id, rederived when the hour turns.
type rotatingID struct {
	secret []byte
	dir    direction
	cur    atomic.Pointer[epochID]
}

type epochID struct {
	epoch int64
	id    connID
}

func (r *rotatingID) at(epoch int64) connID {
	if c := r.cur.Load(); c != nil && c.epoch == epoch {
		return c.id
	}
	c := &epochID{epoch: epoch, id: connIDFor(r.secret, r.dir, epoch)}
	r.cur.Store(c)
	return c.id
}

// idWindow is a receiver's connection ids for the epochs around the current
// one, so clocks a little apart still agree. Not safe for concurrent use.
type idWindow struct {
	valid bool
	epoch int64
	ids   [3]connID
}

func (w *idWindow) recognises(secret []byte, dir direction, epoch int64, id connID) bool {
	if !w.valid || w.epoch != epoch {
		for i := range w.ids {
			w.ids[i] = connIDFor(secret, dir, epoch-1+int64(i))
		}
		w.valid, w.epoch = true, epoch
	}
	return id == w.ids[0] || id == w.ids[1] || id == w.ids[2]
}

func newAEAD(secret []byte, dir direction) cipher.AEAD {
	aead, err := chacha20poly1305.NewX(derive(secret, "key "+string(dir), chacha20poly1305.KeySize))
	if err != nil {
		panic(err)
	}
	return aead
}

// senderID names one end of a link for the receiver's replay filter. Its
// creation time orders senders of the same credential.
type senderID [senderSize]byte

func (s senderID) created() int64 { return int64(binary.BigEndian.Uint64(s[:8])) }

var lastCreated atomic.Int64

func newSenderID(now time.Time) senderID {
	var s senderID
	for {
		last := lastCreated.Load()
		c := max(now.UnixNano(), last+1)
		if lastCreated.CompareAndSwap(last, c) {
			binary.BigEndian.PutUint64(s[:8], uint64(c))
			break
		}
	}
	_, _ = rand.Read(s[8:])
	return s
}

// idOf accepts only datagrams that could hold a packet.
func idOf(d []byte) (connID, bool) {
	var id connID
	if len(d) <= Overhead || len(d) > maxDatagram {
		return id, false
	}
	copy(id[:], d)
	return id, true
}

var plainPool = sync.Pool{New: func() any { b := make([]byte, 0, innerSize+transport.MaxPacketSize); return &b }}

// seal appends the datagram carrying packet to dst.
func seal(dst []byte, aead cipher.AEAD, id connID, sender senderID, now time.Time, counter uint64, packet []byte) []byte {
	dst = append(dst, id[:]...)
	start := len(dst)
	dst = append(dst, make([]byte, nonceSize)...)
	_, _ = rand.Read(dst[start:])
	pp := plainPool.Get().(*[]byte)
	defer plainPool.Put(pp)
	plain := append((*pp)[:0], sender[:]...)
	plain = binary.BigEndian.AppendUint32(plain, uint32(now.Unix()))
	plain = binary.BigEndian.AppendUint64(plain, counter)
	plain = append(plain, packet...)
	*pp = plain
	return aead.Seal(dst, dst[start:], plain, dst[:connIDSize])
}

var errShort = errors.New("udp: datagram too short")

// opened is an authenticated datagram.
type opened struct {
	sender  senderID
	sent    time.Time
	counter uint64
	packet  []byte
}

// fresh reports whether the datagram was sent within maxClockSkew of now.
func (o opened) fresh(now time.Time) bool {
	d := now.Sub(o.sent)
	return d <= maxClockSkew && d >= -maxClockSkew
}

// open authenticates datagram d and appends its plaintext to dst. dst must
// not overlap d unless it is exactly d's ciphertext: on failure Open may
// scribble over dst's capacity.
func open(dst []byte, aead cipher.AEAD, d []byte) (opened, error) {
	plain, err := aead.Open(dst, d[connIDSize:clearSize], d[clearSize:], d[:connIDSize])
	if err != nil {
		return opened{}, err
	}
	if len(plain) <= innerSize {
		return opened{}, errShort
	}
	var o opened
	copy(o.sender[:], plain)
	o.sent = time.Unix(int64(binary.BigEndian.Uint32(plain[senderSize:])), 0)
	o.counter = binary.BigEndian.Uint64(plain[senderSize+sentSize : innerSize])
	o.packet = plain[innerSize:]
	return o, nil
}

var datagramPool = sync.Pool{New: func() any { b := make([]byte, 0, maxDatagram); return &b }}
