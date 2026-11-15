package dns

// TEMPORARY trace for TP-220, removed before review.

import (
	"os"
	"syscall"
)

func statIno(fi os.FileInfo) uint64 { return fi.Sys().(*syscall.Stat_t).Ino }
