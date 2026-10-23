//go:build darwin || linux

package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// The kinds of change the core makes. The set is closed: a plan names
// one, it can't add one.
const (
	// KindFile writes a file of the run's own in its run directory: the
	// self-test's harmless change.
	KindFile = "file"
	// kindCapture runs a tcpdump the helper reads (OpCaptureStart).
	kindCapture = "capture"
	// kindPfSkip loads `set skip on <name>` before the stock pf rules
	// (macOS).
	kindPfSkip = "pf-skip"
)

// Spec is a change as a plan names it and the journal keeps it.
type Spec struct {
	Kind   string          `json:"kind"`
	Params json.RawMessage `json:"params"`
}

// Describe says what spec changes and how it is undone; an error when
// this OS has no such change or its parameters are refused.
func Describe(spec Spec) (does, undo string, err error) {
	a, err := decode(spec)
	if err != nil {
		return "", "", err
	}
	return a.does(), a.undoText(), nil
}

// action is one typed change to the host, with its own undo.
type action interface {
	kind() string
	lifetime() lifetime
	does() string
	undoText() string
	// pre refuses the change when its undo couldn't put the host back.
	pre(ctx context.Context, h *host) error
	// apply makes the change. learnt journals, before apply goes on,
	// what the undo needs that only the change tells (a pid).
	apply(ctx context.Context, h *host, learnt func(json.RawMessage) error) error
	// undo removes the change; it checks first whether the change is
	// there, so it is safe to repeat.
	undo(ctx context.Context, h *host) error
}

func decode(spec Spec) (action, error) {
	switch spec.Kind {
	case KindFile:
		return decodeStrict[fileAction](spec.Params)
	case kindCapture:
		return decodeStrict[captureAction](spec.Params)
	case kindPfSkip:
		return decodePfSkip(spec.Params)
	}
	return nil, fmt.Errorf("no change of kind %q", spec.Kind)
}

// decodeStrict decodes params into a T (a value: JSON null is a zero T,
// which validate refuses), no unknown field allowed.
func decodeStrict[T any, P interface {
	*T
	action
	validate() error
}](params json.RawMessage) (action, error) {
	var v T
	d := json.NewDecoder(bytes.NewReader(params))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("change parameters: %w", err)
	}
	p := P(&v)
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}
