package safety

import "os"

// fullSync puts f's data on the disk: fsync, which on Linux flushes the
// drive's cache too.
func fullSync(f *os.File) error { return f.Sync() }
