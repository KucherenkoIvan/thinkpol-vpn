package lab

import "golang.zx2c4.com/wireguard/device"

// WireGuardHeader reports whether a UDP payload starts like a WireGuard
// message: a message type from 1 to 4 followed by three zero bytes. It is
// the loosest part of the usual DPI signature; random bytes match it about
// once in a billion datagrams.
func WireGuardHeader(payload []byte) bool {
	return len(payload) >= 4 && payload[0] >= 1 && payload[0] <= 4 &&
		payload[1] == 0 && payload[2] == 0 && payload[3] == 0
}

// LooksLikeWireGuard is the usual DPI signature of a WireGuard datagram:
// the header (WireGuardHeader) and the length its type has on the wire
// (148-byte initiations, 92-byte responses, 64-byte cookie replies,
// transport data of at least 32 bytes in 16-byte steps).
func LooksLikeWireGuard(payload []byte) bool {
	if !WireGuardHeader(payload) {
		return false
	}
	switch payload[0] {
	case device.MessageInitiationType:
		return len(payload) == device.MessageInitiationSize
	case device.MessageResponseType:
		return len(payload) == device.MessageResponseSize
	case device.MessageCookieReplyType:
		return len(payload) == device.MessageCookieReplySize
	default:
		return len(payload) >= device.MessageTransportSize && len(payload)%16 == 0
	}
}

// WireGuardOffset is where in a UDP payload a WireGuard message starts
// that runs to the payload's end (LooksLikeWireGuard on the rest), or -1:
// WireGuard behind a header of some other protocol, the way a DPI box that
// scans past a wrapper would find it.
func WireGuardOffset(payload []byte) int {
	for k := range payload {
		if LooksLikeWireGuard(payload[k:]) {
			return k
		}
	}
	return -1
}
