// Package path is the path layer: a conn.Bind that gives WireGuard one stable
// peer and picks between candidate paths (relays, hop group members,
// later direct) underneath, switching with hysteresis.
package path
