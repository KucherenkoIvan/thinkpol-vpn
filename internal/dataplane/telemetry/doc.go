// Package telemetry keeps a node's telemetry in memory only: bounded, each
// record sealed to the space's telemetry key as it is written, oldest dropped
// first. Aggregates per link and device id, never IPs or destinations.
package telemetry
