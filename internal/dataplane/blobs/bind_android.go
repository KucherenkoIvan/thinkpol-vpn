package blobs

import "syscall"

// bindTo binds nothing on Android: an app holds no CAP_NET_RAW for
// SO_BINDTODEVICE, and needs none. VpnService routes the app's own sockets
// into the tunnel unless it protects them, and a device runs no listener
// (PlanFrom).
func bindTo(string) func(network, address string, c syscall.RawConn) error { return nil }
