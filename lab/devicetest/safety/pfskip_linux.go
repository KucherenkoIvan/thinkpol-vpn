package safety

import (
	"encoding/json"
	"errors"
)

func decodePfSkip(json.RawMessage) (action, error) {
	return nil, errors.New("pf-skip: macOS only")
}
