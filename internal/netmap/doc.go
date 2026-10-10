// Package netmap is the signed network map: the envelope, sealed per-node
// sections, signing, verification and gossip. See DESIGN.md "The signed map".
//
// Both planes use it: the controller builds maps, every node reads its own
// section without the controller. Pure Go, buildable for Android.
package netmap
