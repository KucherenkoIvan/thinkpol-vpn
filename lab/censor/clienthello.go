package censor

import (
	"encoding/binary"
	"errors"
)

// TLS framing (RFC 8446 section 5.1, 4).
const (
	tlsRecordHeader    = 5
	tlsHandshake       = 22 // record content type
	tlsClientHello     = 1  // handshake message type
	tlsMaxRecord       = 1<<14 + 2048
	tlsExtServerName   = 0
	tlsServerNameHost  = 0
	tlsHandshakeHeader = 4
)

// errNotClientHello says a stream doesn't start with a TLS ClientHello,
// or starts with one that is malformed.
var errNotClientHello = errors.New("not a TLS ClientHello")

// errIncomplete says the stream holds the start of a ClientHello but not
// all of it yet.
var errIncomplete = errors.New("ClientHello incomplete")

// clientHelloServerName reads the server name a stream's ClientHello asks
// for, "" when it names none, from the stream's first bytes. The message
// may be split over any number of handshake records (a record-fragmenting
// client, or one evading a censor that reads only the first record) and
// those over any number of segments, which the stream has put in order:
// until all of it is there, errIncomplete. Anything else at the stream's
// start is errNotClientHello.
func clientHelloServerName(b []byte) (string, error) {
	msg, err := clientHelloMessage(b)
	if err != nil {
		return "", err
	}
	return serverName(msg)
}

// clientHelloMessage reassembles the ClientHello's body from the handshake
// records at b's start.
func clientHelloMessage(b []byte) ([]byte, error) {
	var msg []byte
	for {
		if len(b) < tlsRecordHeader {
			return nil, errIncomplete
		}
		n := int(binary.BigEndian.Uint16(b[3:]))
		// Versions 3.0 to 3.4 on the record layer; a ClientHello's says
		// 3.1 or 3.3, but censors match the major byte.
		if b[0] != tlsHandshake || b[1] != 3 || b[2] > 4 || n == 0 || n > tlsMaxRecord {
			return nil, errNotClientHello
		}
		if len(msg) == 0 && len(b) > tlsRecordHeader && b[tlsRecordHeader] != tlsClientHello {
			return nil, errNotClientHello
		}
		if len(b) < tlsRecordHeader+n {
			msg = append(msg, b[tlsRecordHeader:]...)
			if err := plausibleHello(msg); err != nil {
				return nil, err
			}
			return nil, errIncomplete
		}
		msg = append(msg, b[tlsRecordHeader:tlsRecordHeader+n]...)
		b = b[tlsRecordHeader+n:]
		if err := plausibleHello(msg); err != nil {
			return nil, err
		}
		if len(msg) >= tlsHandshakeHeader {
			want := tlsHandshakeHeader + uint24(msg[1:])
			if len(msg) >= want {
				return msg[tlsHandshakeHeader:want], nil
			}
		}
	}
}

// plausibleHello rejects a handshake message that can't be a ClientHello
// a stream prefix could hold, before waiting for the rest of it.
func plausibleHello(msg []byte) error {
	if len(msg) < tlsHandshakeHeader {
		return nil
	}
	if msg[0] != tlsClientHello || uint24(msg[1:]) > retainBytes {
		return errNotClientHello
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
	if _, ok := r.vector(1); !ok {
		return "", errNotClientHello
	}
	if _, ok := r.vector(2); !ok {
		return "", errNotClientHello
	}
	if _, ok := r.vector(1); !ok {
		return "", errNotClientHello
	}
	if len(r) == 0 {
		return "", nil // no extensions at all (TLS 1.2 allows it)
	}
	exts, ok := r.vector(2)
	if !ok || len(r) != 0 {
		return "", errNotClientHello
	}
	for len(exts) > 0 {
		typ, ok := exts.uint16()
		if !ok {
			return "", errNotClientHello
		}
		data, ok := exts.vector(2)
		if !ok {
			return "", errNotClientHello
		}
		if typ != tlsExtServerName {
			continue
		}
		list, ok := data.vector(2)
		if !ok || len(data) != 0 {
			return "", errNotClientHello
		}
		for len(list) > 0 {
			kind, ok := list.uint8()
			if !ok {
				return "", errNotClientHello
			}
			name, ok := list.vector(2)
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

// vector reads a length-prefixed field whose length takes lenBytes (1 or
// 2) bytes.
func (r *reader) vector(lenBytes int) (reader, bool) {
	var n int
	switch lenBytes {
	case 1:
		v, ok := r.uint8()
		if !ok {
			return nil, false
		}
		n = int(v)
	default:
		v, ok := r.uint16()
		if !ok {
			return nil, false
		}
		n = int(v)
	}
	if len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}
