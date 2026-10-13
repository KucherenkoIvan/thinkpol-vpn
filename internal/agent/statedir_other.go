//go:build !darwin

package agent

// DefaultStateDir is where a node keeps its keys and its map, and nothing
// else (PRD S1).
const DefaultStateDir = "/var/lib/thinkpol"
