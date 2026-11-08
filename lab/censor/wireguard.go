package censor

// WireGuard's message types and their sizes on the wire (the WireGuard
// paper, section 5.4).
const (
	wgTypeInitiation  = 1
	wgTypeResponse    = 2
	wgTypeCookieReply = 3
	wgTypeTransport   = 4
	wgInitiation      = 148
	wgResponse        = 92
	wgCookieReply     = 64
	// wgTransportMin is an empty transport message, a keepalive: header,
	// receiver index, counter and tag. The kernel pads a transport
	// message's payload to 16 bytes but not past the MTU (send.c,
	// calculate_skb_padding), so a full-MTU message has any length.
	wgTransportMin = 32
)
