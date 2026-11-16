//go:build !linux

package censor

import (
	"context"
	"errors"
)

// Run never runs: the censor serves an NFQUEUE, Linux only. It exists so
// censord builds where the lab is not (lint vets every OS); the lab only
// ever starts the Linux binary.
func Run(ctx context.Context, cfg Config, eng *Engine) error {
	return errors.New("censor: NFQUEUE runs only on Linux, in the lab's router")
}

// ClearRouter never runs, as Run doesn't.
func ClearRouter() error {
	return errors.New("censor: the censor's reset runs only on Linux, in the lab's router")
}
