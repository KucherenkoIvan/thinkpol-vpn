package censor

import (
	"encoding/binary"
	"errors"
)

// TLS framing (RFC 8446 section 5.1, 4).
const (
	tlsRecordHeader    = 5
	tlsHandshake       = 22 // record content type
	tlsClientHello     = 1  // handshake message types
	tlsServerHello     = 2
	tlsMaxRecord       = 1<<14 + 2048
	tlsExtServerName   = 0
	tlsServerNameHost  = 0
	tlsHandshakeHeader = 4
)

// errNotClientHello and errNotServerHello say a stream doesn't start with
// that hello, or starts with one that is malformed.
var (
	errNotClientHello = errors.New("not a TLS ClientHello")
	errNotServerHello = errors.New("not a TLS ServerHello")
)

// errIncomplete says the stream holds the start of a hello but not all of
// it yet.
var errIncomplete = errors.New("hello incomplete")

// errHelloTooLong says the stream starts with a hello whose handshake
// message is longer than retainBytes: the censor never holds all of it.
var errHelloTooLong = errors.New("hello longer than the censor keeps")

// clientHelloServerName reads the server name a stream's ClientHello asks
// for, "" when it names none, from the stream's first bytes. The message
// may be split over any number of handshake records (a record-fragmenting
// client, or one evading a censor that reads only the first record) and
// those over any number of segments, which the stream has put in order:
// until all of it is there, errIncomplete. A ClientHello longer than
// retainBytes is errHelloTooLong; anything else at the stream's start is
// errNotClientHello.
func clientHelloServerName(b []byte) (string, error) {
	msg, _, err := helloMessage(b, tlsClientHello)
	if err != nil {
		return "", err
	}
	return serverName(msg)
}

// helloMessage reassembles the body of the hello of type typ (a
// ClientHello or a ServerHello) from the handshake records at b's start,
// and says how many bytes of b its records took.
func helloMessage(b []byte, typ byte) (body []byte, used int, err error) {
	notIt := errNotClientHello
	if typ == tlsServerHello {
		notIt = errNotServerHello
	}
	var msg []byte
	for whole := b; ; {
		if len(b) < tlsRecordHeader {
			return nil, 0, errIncomplete
		}
		rec := int(binary.BigEndian.Uint16(b[3:]))
		// The record layer's version: major 3, minor 0 to 4 (a
		// ClientHello's says 3.1 or 3.3, but any of them is TLS).
		if b[0] != tlsHandshake || b[1] != 3 || b[2] > 4 || rec == 0 || rec > tlsMaxRecord {
			return nil, 0, notIt
		}
		if len(msg) == 0 && len(b) > tlsRecordHeader && b[tlsRecordHeader] != typ {
			return nil, 0, notIt
		}
		if len(b) < tlsRecordHeader+rec {
			msg = append(msg, b[tlsRecordHeader:]...)
			if err := plausibleHello(msg, typ, notIt); err != nil {
				return nil, 0, err
			}
			return nil, 0, errIncomplete
		}
		msg = append(msg, b[tlsRecordHeader:tlsRecordHeader+rec]...)
		b = b[tlsRecordHeader+rec:]
		if err := plausibleHello(msg, typ, notIt); err != nil {
			return nil, 0, err
		}
		if len(msg) >= tlsHandshakeHeader {
			want := tlsHandshakeHeader + uint24(msg[1:])
			if len(msg) >= want {
				return msg[tlsHandshakeHeader:want], len(whole) - len(b), nil
			}
		}
	}
}

// plausibleHello rejects a handshake message that can't be a hello of
// type typ (notIt) or that a stream prefix can't hold (errHelloTooLong),
// before waiting for the rest of it.
func plausibleHello(msg []byte, typ byte, notIt error) error {
	switch {
	case len(msg) < tlsHandshakeHeader:
		return nil
	case msg[0] != typ:
		return notIt
	case uint24(msg[1:]) > retainBytes:
		return errHelloTooLong
	}
	return nil
}

func uint24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// serverName walks a ClientHello's body (RFC 8446 section 4.1.2) to its
// server_name extension (RFC 6066 section 3) and returns the host name.
func serverName(body []byte) (string, error) {
	r := reader(body)
	// legacy_version, random
	if !r.skip(2 + 32) {
		return "", errNotClientHello
	}
	// legacy_session_id, cipher_suites, legacy_compression_methods
	if _, ok := r.vector8(); !ok {
		return "", errNotClientHello
	}
	if _, ok := r.vector16(); !ok {
		return "", errNotClientHello
	}
	if _, ok := r.vector8(); !ok {
		return "", errNotClientHello
	}
	if len(r) == 0 {
		return "", nil // no extensions at all (TLS 1.2 allows it)
	}
	exts, ok := r.vector16()
	if !ok || len(r) != 0 {
		return "", errNotClientHello
	}
	for len(exts) > 0 {
		typ, ok := exts.uint16()
		if !ok {
			return "", errNotClientHello
		}
		data, ok := exts.vector16()
		if !ok {
			return "", errNotClientHello
		}
		if typ != tlsExtServerName {
			continue
		}
		list, ok := data.vector16()
		if !ok || len(data) != 0 {
			return "", errNotClientHello
		}
		for len(list) > 0 {
			kind, ok := list.uint8()
			if !ok {
				return "", errNotClientHello
			}
			name, ok := list.vector16()
			if !ok {
				return "", errNotClientHello
			}
			if kind == tlsServerNameHost {
				return string(name), nil
			}
		}
		return "", nil
	}
	return "", nil
}

// reader reads TLS presentation-language fields off the front of a slice.
type reader []byte

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) uint8() (uint8, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v, true
}

func (r *reader) uint16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(*r)
	*r = (*r)[2:]
	return v, true
}

// vector8 reads a field behind a 1-byte length.
func (r *reader) vector8() (reader, bool) {
	n, ok := r.uint8()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

// vector16 reads a field behind a 2-byte length.
func (r *reader) vector16() (reader, bool) {
	n, ok := r.uint16()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

func (r *reader) take(n int) (reader, bool) {
	if len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}
