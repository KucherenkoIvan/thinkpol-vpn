// Package wg runs the WireGuard devices (wireguard-go/device), one per
// egress, which carry end-to-end sessions with peers (devices, exits).
// WireGuard routes by allowed IPs, and two exits would both claim the
// default route, so each egress gets a device of its own: the overlay
// device for device-to-device peers and every peer that isn't a chain's
// exit, and one device for each exit that a chain the routing rules use
// sends traffic to (see package dataplane's layout and DESIGN.md "Routing
// rules and DNS").
//
// WireGuard is the inner layer only and never touches the network: each
// device reads a router egress as its TUN, and its only network is a
// path.Bind, so it has no socket, no listen port and no firewall mark.
// Peers' endpoints are their node ids. [Overhead] is what WireGuard adds to
// each packet: a TUN's MTU is the path layer's message budget less this.
//
// Devices are configured through wireguard-go's Go API (IpcSet), never a
// UAPI socket, with the whole desired state; only what changed is touched,
// so sessions survive map updates, and a peer that stays keeps the
// endpoint WireGuard last adopted for it, which tells the Bind the path the
// peer chose.
package wg
