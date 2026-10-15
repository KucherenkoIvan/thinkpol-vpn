package wg

func IpcGetForTest(d *Device) string {
	s, _ := d.dev.IpcGet()
	return s
}

// PeerName is how WireGuard names a peer in its messages.
var PeerName = peerName
