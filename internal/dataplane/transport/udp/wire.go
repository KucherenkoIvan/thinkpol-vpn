package udp

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Wire format:
//
//	conn id [8] | nonce [24] | XChaCha20-Poly1305(sender [12] | sent [4] | counter [8] | frames | padding)
//	frame: length [2] | packet [length]
//
// See the package documentation for what each part is for.
const (
	connIDSize  = 8
	nonceSize   = chacha20poly1305.NonceSizeX
	senderSize  = 12 // creation time in Unix nanoseconds [8] | random [4]
	sentSize    = 4  // Unix seconds, uint32
	counterSize = 8
	tagSize     = chacha20poly1305.Overhead
	frameHeader = 2 // packet length, big endian

	clearSize = connIDSize + nonceSize
	innerSize = senderSize + sentSize + counterSize

	// Overhead is what udp adds to a packet sent alone and unpadded,
	// before IP and UDP headers.
	Overhead = clearSize + innerSize + frameHeader + tagSize

	// MaxRandomPadding is the most random padding udp adds. It keeps the
	// largest datagram under macOS's default limit of 9216 bytes.
	MaxRandomPadding = 512

	// minDatagram carries no packet (cover); maxDatagram is the largest
	// datagram udp sends or accepts, and the largest bucket it pads to.
	minDatagram = clearSize + innerSize + tagSize
	maxDatagram = Overhead + transport.MaxPacketSize + MaxRandomPadding

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

// idOf accepts only datagrams of a size udp sends.
func idOf(d []byte) (connID, bool) {
	var id connID
	if len(d) < minDatagram || len(d) > maxDatagram {
		return id, false
	}
	copy(id[:], d)
	return id, true
}

var plainPool = sync.Pool{New: func() any { b := make([]byte, 0, maxDatagram); return &b }}

// support is the shaping udp implements: padding. Batching, jitter and
// cover traffic it refuses; receivers already take several packets, or
// none, per datagram.
var support = transport.ShapingSupport{Padding: true}

func checkShaping(s transport.Shaping) error {
	if err := support.Check(s); err != nil {
		return fmt.Errorf("udp: %w", err)
	}
	p := s.Padding
	if int(p.Max) > MaxRandomPadding {
		return fmt.Errorf("udp: %w: random padding up to %d bytes, udp adds at most %d", transport.ErrUnsupportedShaping, p.Max, MaxRandomPadding)
	}
	for _, b := range p.Buckets {
		if int(b) > maxDatagram {
			return fmt.Errorf("udp: %w: a bucket of %d bytes, udp sends at most %d", transport.ErrUnsupportedShaping, b, maxDatagram)
		}
	}
	return nil
}

// seal appends the datagram carrying packet, padded as padding says, to
// dst.
func seal(dst []byte, aead cipher.AEAD, id connID, sender senderID, now time.Time, counter uint64, packet []byte, padding transport.Padding) []byte {
	dst = append(dst, id[:]...)
	start := len(dst)
	dst = append(dst, make([]byte, nonceSize)...)
	_, _ = rand.Read(dst[start:])
	pp := plainPool.Get().(*[]byte)
	defer plainPool.Put(pp)
	plain := append((*pp)[:0], sender[:]...)
	plain = binary.BigEndian.AppendUint32(plain, uint32(now.Unix()))
	plain = binary.BigEndian.AppendUint64(plain, counter)
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(packet)))
	plain = append(plain, packet...)
	if pad := padding.Size(Overhead+len(packet)) - Overhead - len(packet); pad > 0 {
		// zeros: a zero length ends the frames. The pool's buffers hold
		// maxDatagram, so this never allocates.
		n := len(plain)
		plain = slices.Grow(plain, pad)[:n+pad]
		clear(plain[n:])
	}
	*pp = plain
	return aead.Seal(dst, dst[start:], plain, dst[:connIDSize])
}

var (
	errShort     = errors.New("udp: datagram too short")
	errMalformed = errors.New("udp: malformed frames")
)

// opened is an authenticated datagram.
type opened struct {
	sender  senderID
	sent    time.Time
	counter uint64
	frames  []byte // checked: nextFrame splits it without failing
	packets int    // in frames; none is a cover datagram
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
	if len(plain) < innerSize {
		return opened{}, errShort
	}
	var o opened
	copy(o.sender[:], plain)
	o.sent = time.Unix(int64(binary.BigEndian.Uint32(plain[senderSize:])), 0)
	o.counter = binary.BigEndian.Uint64(plain[senderSize+sentSize : innerSize])
	o.frames = plain[innerSize:]
	for rest := o.frames; ; o.packets++ {
		n, ok := frameLen(rest)
		if !ok {
			break
		}
		if n > transport.MaxPacketSize || n > len(rest)-frameHeader {
			return opened{}, errMalformed
		}
		rest = rest[frameHeader+n:]
	}
	return o, nil
}

// frameLen reads the length of the next frame. The frames end at a zero
// length or with fewer than two bytes left; what follows is padding.
func frameLen(frames []byte) (int, bool) {
	if len(frames) < frameHeader {
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(frames))
	return n, n != 0
}

// nextFrame splits the next packet off frames that open checked; packet is
// nil once they end.
func nextFrame(frames []byte) (packet, rest []byte) {
	n, ok := frameLen(frames)
	if !ok {
		return nil, nil
	}
	return frames[frameHeader : frameHeader+n], frames[frameHeader+n:]
}

var datagramPool = sync.Pool{New: func() any { b := make([]byte, 0, maxDatagram); return &b }}
