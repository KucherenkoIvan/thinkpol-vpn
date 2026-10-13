//go:build !windows

package dns

// isMessageSize reports a datagram too big for the read buffer; here the
// read truncates it instead of failing, and the size check catches it.
func isMessageSize(error) bool { return false }
