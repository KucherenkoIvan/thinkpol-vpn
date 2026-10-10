// Package netmap is the signed network map: the envelope, sealed per-node
// sections, signing, verification and gossip. See DESIGN.md "The signed map".
//
// No cgo here and no imports from internal/features: every node, devices
// included, reads the map without the controller.
package netmap
