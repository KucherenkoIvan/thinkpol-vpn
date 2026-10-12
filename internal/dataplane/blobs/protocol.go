package blobs

import (
	"encoding/binary"
	"errors"
)

// Port is the service's TCP port on every node's overlay addresses.
const Port uint16 = 4717

const (
	protocolVersion = 1
	requestSize     = 4 + 32 + 8
	// responseHeaderSize is a statusOK response's status and length.
	responseHeaderSize = 1 + 8
)

var requestMagic = [3]byte{'T', 'P', 'B'}

// status is a response's first byte.
type status byte

const (
	statusOK status = iota
	// statusNotHere: the server holds no such blob (or won't say).
	statusNotHere
	// statusBusy: the server has no room for another transfer now.
	statusBusy
	// statusBadRequest: the request was malformed or its offset past the
	// blob's end.
	statusBadRequest
)

type request struct {
	sha256 [32]byte
	offset uint64
}

func (r request) encode() [requestSize]byte {
	var b [requestSize]byte
	copy(b[:3], requestMagic[:])
	b[3] = protocolVersion
	copy(b[4:36], r.sha256[:])
	binary.BigEndian.PutUint64(b[36:], r.offset)
	return b
}

var errBadRequest = errors.New("blobs: malformed request")

func decodeRequest(b [requestSize]byte) (request, error) {
	if [3]byte(b[:3]) != requestMagic || b[3] != protocolVersion {
		return request{}, errBadRequest
	}
	return request{sha256: [32]byte(b[4:36]), offset: binary.BigEndian.Uint64(b[36:])}, nil
}
