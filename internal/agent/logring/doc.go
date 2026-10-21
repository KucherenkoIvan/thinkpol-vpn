// Package logring keeps an agent's logs in memory only (PRD S2): a bounded
// ring of lines, oldest dropped first, gone when the process exits.
//
// A [Ring] is an io.Writer that splits what it gets into lines, so a slog
// handler or a child process's output can write to it directly; a line
// longer than [MaxLine] is cut there and goes on in the next one, so a
// writer without newlines can't grow the ring past its size. A reader
// following the log ([Ring.Since]) gets every line once and is told how
// many were dropped before it read them.
//
// The node agent writes its log here besides stderr (agent.NewLogs), and
// the local API serves it to root only (TailLogs). Nothing of it is ever
// written to disk.
package logring
