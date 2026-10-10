package shared

// Pins go-kernel in go.mod until real code imports it, so `go mod tidy`
// doesn't drop it. Delete this file then.
import _ "github.com/KucherenkoIvan/go-kernel/ddd"
