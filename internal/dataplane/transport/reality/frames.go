package reality

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Framing inside the TLS records. Each unit, one write and so one record,
// is a packet frame and, when shaping pads it, a padding frame:
//
//	packet:  length [2] (1 to 8192, top bit clear) | packet
//	padding: 0b11 | length [14 bits] | zeros [length]   or   0x80 (one byte)
//
// The receiver reads frames off the stream and never needs record
// boundaries, so it undoes padding from the wire alone.
const (
	frameHeader = 2
	padOne      = 0x80
	padMark     = 0xc0

	// recordOverhead is what TLS 1.3 adds to a record's plaintext: the
	// header, the inner content type and the AEAD tag.
	recordOverhead = recordHeaderSize + 1 + 16
	// maxPlaintext is the most a TLS record carries.
	maxPlaintext = 1 << 14

	// Overhead is what reality adds to a packet sent unpadded, before IP
	// and TCP headers.
	Overhead = recordOverhead + frameHeader
	// MaxRandomPadding is the most random padding reality adds.
	MaxRandomPadding = 1024
	// maxUnit is the largest record reality writes, and the largest bucket
	// it pads to.
	maxUnit = maxPlaintext + recordOverhead
)

var errMalformed = errors.New("reality: malformed frame")

// appendUnit appends the plaintext of the record carrying packet, padded
// as padding says.
func appendUnit(dst, packet []byte, padding transport.Padding) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(packet)))
	dst = append(dst, packet...)
	unpadded := frameHeader + len(packet) + recordOverhead
	return appendPadding(dst, padding.Size(unpadded)-unpadded)
}

func appendPadding(dst []byte, n int) []byte {
	switch {
	case n <= 0:
		return dst
	case n == 1:
		return append(dst, padOne)
	}
	zeros := n - frameHeader
	dst = append(dst, padMark|byte(zeros>>8), byte(zeros))
	return append(dst, make([]byte, zeros)...)
}

// readPacket reads frames off r until a packet, copying it into p. A
// packet that doesn't fit is skipped and io.ErrShortBuffer returned; any
// other error ends the stream.
func readPacket(r *bufio.Reader, p []byte) (int, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if b == padOne {
			continue
		}
		lo, err := r.ReadByte()
		if err != nil {
			return 0, unexpected(err)
		}
		n := int(b&0x3f)<<8 | int(lo)
		switch {
		case b&padMark == padMark:
			if _, err := r.Discard(n); err != nil {
				return 0, unexpected(err)
			}
			continue
		case b&padOne != 0:
			return 0, fmt.Errorf("%w: header %#x", errMalformed, b)
		}
		n = int(b)<<8 | int(lo)
		if n == 0 || n > transport.MaxPacketSize {
			return 0, fmt.Errorf("%w: a %d-byte packet", errMalformed, n)
		}
		if n > len(p) {
			if _, err := r.Discard(n); err != nil {
				return 0, unexpected(err)
			}
			return 0, io.ErrShortBuffer
		}
		if _, err := io.ReadFull(r, p[:n]); err != nil {
			return 0, unexpected(err)
		}
		return n, nil
	}
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
