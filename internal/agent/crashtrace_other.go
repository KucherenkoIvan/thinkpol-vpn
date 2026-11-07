//go:build !unix

package agent

import "os"

const noFollow = 0

// fixCrashTraceFile does nothing: no service sends the agent's stderr to
// a file here (the Windows service is TP-047's).
func fixCrashTraceFile(*os.File, os.FileInfo) (string, error) { return "", nil }
