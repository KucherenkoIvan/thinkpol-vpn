package shared

// Pins go-kernel in go.mod until real code imports it, so `go mod tidy`
// doesn't drop it. TP-034 (the controller core) deletes this file.
import _ "github.com/KucherenkoIvan/go-kernel/ddd"
