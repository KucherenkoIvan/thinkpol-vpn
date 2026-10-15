// Throwaway VLESS request code for the TP-064 prototype: just enough of
// VLESS version 0 (no flow, one TCP request) to prove the authenticated
// REALITY session carries application data to a stock Xray server. Not a
// VLESS client, not for internal/.
package reality

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// VLESS address types (proxy/vless/encoding headers).
const (
	addrIPv4   = 0x01
	addrDomain = 0x02
	addrIPv6   = 0x03
	commandTCP = 0x01
)

// VLESSRequest builds a version-0 TCP request: a 16-byte user id, no addons,
// no flow, then the address, followed by the first payload bytes.
func VLESSRequest(userID [16]byte, addr netip.Addr, port uint16, payload []byte) []byte {
	b := []byte{0x00} // protocol version
	b = append(b, userID[:]...)
	b = append(b, 0x00) // addons length: no flow
	b = append(b, commandTCP)
	b = binary.BigEndian.AppendUint16(b, port)
	if addr.Is4() {
		a4 := addr.As4()
		b = append(b, addrIPv4)
		b = append(b, a4[:]...)
	} else {
		a16 := addr.As16()
		b = append(b, addrIPv6)
		b = append(b, a16[:]...)
	}
	return append(b, payload...)
}

// VLESSResponse reads the version-0 response header (version byte plus an
// empty addons blob) and leaves the rest of the stream to the caller.
func VLESSResponse(r io.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("vless: read response header: %w", err)
	}
	if header[0] != 0x00 {
		return fmt.Errorf("vless: response version %d", header[0])
	}
	if header[1] != 0x00 {
		return errors.New("vless: unexpected response addons")
	}
	return nil
}
