// Package wg runs the WireGuard devices (wireguard-go/device), one per
// egress: the overlay device for device-to-device peers, and later one per
// chain, because WireGuard routes by allowed IPs and two exits would both
// claim the default route. WireGuard is the inner layer only and never
// touches the network: each device reads a router egress as its TUN, and
// its only network is a path.Bind, so it has no socket, no listen port and
// no firewall mark. Peers' endpoints are their node ids.
//
// Devices are configured through wireguard-go's Go API (IpcSet), never a
// UAPI socket, with the whole desired state; only what changed is touched,
// so sessions survive map updates.
package wg
