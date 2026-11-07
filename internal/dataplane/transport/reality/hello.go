package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// The session id seal, REALITY's wire format (TP-064's Notes):
//
//	session id [32] = AES-256-GCM(key, nonce = Random[20:32],
//	    version [3] | 0 | Unix seconds [4] | short id [8],
//	    additional data = the ClientHello handshake message, session id zeroed)
//	key = HKDF-SHA256(X25519(client share, listener key), salt = Random[:20], info "REALITY")
const (
	recordHeaderSize = 5
	handshakeHeader  = 4
	// sessionIDOffset is where the session id starts in the handshake
	// message: header [4], legacy version [2], random [32], length [1].
	sessionIDOffset = handshakeHeader + 2 + 32 + 1
	sessionIDSize   = 32
	sealedSize      = 16
	kdfInfo         = "REALITY"

	recordTypeHandshake = 22
	typeClientHello     = 1
	// maxHelloRecord bounds the one record a ClientHello must fit in.
	maxHelloRecord = 1 << 14

	extServerName        = 0
	extSupportedVersions = 43
	extKeyShare          = 51
	versionTLS13         = 0x0304
	groupX25519          = 0x001d
	groupX25519MLKEM768  = 0x11ec
	mlkem768KeySize      = 1184
)

// sealedVersion is what the client puts in the seal's version bytes. The
// listener sets no version bounds, so it only has to be fixed.
var sealedVersion = [3]byte{0, 0, 0}

var errHello = errors.New("reality: not a ClientHello the listener takes")

// clientHello is what the listener reads from a ClientHello before
// answering anything.
type clientHello struct {
	msg        []byte // the handshake message, header included
	random     []byte
	sessionID  []byte // inside msg
	serverName string
	tls13      bool
	// share is the client's X25519 public key the seal is keyed with: the
	// standalone X25519 share if there is one, else the X25519 half of
	// X25519MLKEM768. A hello without X25519MLKEM768 before its X25519
	// share is refused, as the REALITY server it meets refuses it.
	share []byte
}

// parseHello reads a ClientHello from record, one whole TLS record that
// holds it alone.
func parseHello(record []byte) (*clientHello, error) {
	if len(record) < recordHeaderSize || record[0] != recordTypeHandshake ||
		int(binary.BigEndian.Uint16(record[3:5])) != len(record)-recordHeaderSize {
		return nil, errHello
	}
	h := &clientHello{msg: record[recordHeaderSize:]}
	in := cryptobyte.String(h.msg)
	var typ uint8
	var body cryptobyte.String
	if !in.ReadUint8(&typ) || typ != typeClientHello || !in.ReadUint24LengthPrefixed(&body) || !in.Empty() {
		return nil, errHello
	}
	var version uint16
	var sessionID, suites, compression, exts cryptobyte.String
	if !body.ReadUint16(&version) || !body.ReadBytes(&h.random, 32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) || len(sessionID) != sessionIDSize ||
		!body.ReadUint16LengthPrefixed(&suites) || !body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&exts) || !body.Empty() {
		return nil, errHello
	}
	h.sessionID = h.msg[sessionIDOffset : sessionIDOffset+sessionIDSize]
	seen := map[uint16]bool{}
	for !exts.Empty() {
		var ext uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&ext) || !exts.ReadUint16LengthPrefixed(&data) || seen[ext] {
			return nil, errHello
		}
		seen[ext] = true
		var ok bool
		switch ext {
		case extServerName:
			h.serverName, ok = readServerName(data)
		case extSupportedVersions:
			h.tls13, ok = offersTLS13(data)
		case extKeyShare:
			h.share, ok = readShare(data)
		default:
			ok = true
		}
		if !ok {
			return nil, errHello
		}
	}
	if !h.tls13 || h.share == nil || h.serverName == "" {
		return nil, errHello
	}
	return h, nil
}

func readServerName(data cryptobyte.String) (string, bool) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
		return "", false
	}
	for !list.Empty() {
		var typ uint8
		var name cryptobyte.String
		if !list.ReadUint8(&typ) || !list.ReadUint16LengthPrefixed(&name) {
			return "", false
		}
		if typ == 0 {
			return string(name), true
		}
	}
	return "", false
}

func offersTLS13(data cryptobyte.String) (bool, bool) {
	var list cryptobyte.String
	if !data.ReadUint8LengthPrefixed(&list) || !data.Empty() {
		return false, false
	}
	found := false
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return false, false
		}
		found = found || v == versionTLS13
	}
	return found, true
}

// readShare picks the X25519 key the seal is keyed with; nil means none
// usable, which refuses the hello.
func readShare(data cryptobyte.String) ([]byte, bool) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
		return nil, false
	}
	var hybrid, x25519 []byte
	for !list.Empty() && x25519 == nil {
		var group uint16
		var key cryptobyte.String
		if !list.ReadUint16(&group) || !list.ReadUint16LengthPrefixed(&key) {
			return nil, false
		}
		switch {
		case group == groupX25519MLKEM768 && len(key) == mlkem768KeySize+32:
			if hybrid != nil {
				return nil, true
			}
			hybrid = key[mlkem768KeySize:]
		case group == groupX25519 && len(key) == 32:
			x25519 = key
		}
	}
	switch {
	case hybrid == nil:
		return nil, true
	case x25519 != nil:
		return x25519, true
	}
	return hybrid, true
}

// sealKey derives the seal's AEAD from the X25519 shared secret.
func sealKey(shared, random []byte) (authKey []byte, aead cipher.AEAD, err error) {
	authKey, err = hkdf.Key(sha256.New, shared, random[:20], kdfInfo, 32)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, nil, err
	}
	aead, err = cipher.NewGCM(block)
	return authKey, aead, err
}

// sealedHello is what an opened session id says.
type sealedHello struct {
	shortID shortID
	sent    uint32 // Unix seconds, wraps in 2106
}

// open authenticates h's session id with the listener's key.
func open(key *ecdh.PrivateKey, h *clientHello) (sealedHello, error) {
	var s sealedHello
	pub, err := ecdh.X25519().NewPublicKey(h.share)
	if err != nil {
		return s, err
	}
	shared, err := key.ECDH(pub)
	if err != nil {
		return s, err
	}
	_, aead, err := sealKey(shared, h.random)
	if err != nil {
		return s, err
	}
	aad := make([]byte, len(h.msg))
	copy(aad, h.msg)
	clear(aad[sessionIDOffset : sessionIDOffset+sessionIDSize])
	plain, err := aead.Open(nil, h.random[20:32], h.sessionID, aad)
	if err != nil {
		return s, err
	}
	if len(plain) != sealedSize {
		return s, errHello
	}
	s.sent = binary.BigEndian.Uint32(plain[4:8])
	copy(s.shortID[:], plain[8:])
	return s, nil
}

// seal writes the session id into msg, a ClientHello handshake message
// whose session id is still zero.
func seal(aead cipher.AEAD, msg, random []byte, id shortID, sent uint32) {
	plain := make([]byte, 0, sealedSize)
	plain = append(plain, sealedVersion[:]...)
	plain = append(plain, 0)
	plain = binary.BigEndian.AppendUint32(plain, sent)
	plain = append(plain, id[:]...)
	aad := make([]byte, len(msg)) // GCM's output must not overlap its additional data
	copy(aad, msg)
	aead.Seal(msg[sessionIDOffset:sessionIDOffset], random[20:32], plain, aad)
}
